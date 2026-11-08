# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The system's trusted roots, on every node (1.0.59, as otp 1.0.265)
# ---------------------------------------------------------------------------
# Settings → Certificates and TLS → Trusted roots of the system: certificate authorities of
# one's own (a company's root, an intermediate) put into the trust of the operating system as a
# whole - curl, dnf, LDAPS to a domain controller, SMTP, syslog over TLS and acme's own
# connections. Each node's root helper (acme_web.py, osroots.ask) puts them where the system
# itself takes local additions from (the anchors folder of RHEL, /usr/local/share/ca-certificates
# of Debian) and runs the system's own tool; the distribution's list is never touched and keeps
# coming with the system's updates, these beside it. Only files named acme-<sha256 16>.pem|.crt
# are ever written or taken away; anything else in that folder is somebody else's and only shown.
#
# The set wanted is the cluster's: each node writes only a row of its own,
# 'oscerts:want:NODE' = {v, certs, by, at, what} - the newest v of all of them is the set (v
# counted above every v seen, so the order does not hang on the clocks; a tie goes by the row's
# name); signed by the database guard, as every row that reaches root. Each node's daemon has its
# root helper bring the machine to that set - when it changes, at its start, every half hour -
# and says how it went, with what the machine has, in 'oscerts:node:NODE' (no PEMs).
# 'oscerts:again:NODE' asks every node to read again.
OSR_MAX = 50                    # certificates of acme's at most
OSR_PEM_MAX = 16384             # one certificate, as PEM
OSR_RESYNC_S = 1800             # brought to the set again every half hour
OSR_RETRY_S = 600               # a set that failed tried again after ten minutes
OSR_LATE_S = 300                # waiting longer than this: the hint said
OSR_STALE_S = 900               # a run that never ended is forgotten after this
OSR = {'busy': False, 'since': 0.0, 'done_hash': None, 'done_at': 0.0, 'fail_hash': None,
       'fail_at': 0.0, 'again_seen': None}
OSR_LOCK = threading.Lock()
OSR_BLOCK_RE = re.compile(r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----')
OSR_PY = {'fixed': ''}
OSR_SYSTEM_BUNDLES = ('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
                      '/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt')


def _osr_obj(text):
    try:
        got = json.loads(text) if text else None
    except (TypeError, ValueError):
        return None
    return got if isinstance(got, dict) else None


def _osr_num(v):
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


# -- acme's own connections and the system's trust ---------------------------------------
def osr_python_fix():
    """acme's own TLS clients (the directory, mail, syslog, SMS, ACME, isemon, the remote
    backups) make their contexts with ssl.create_default_context(), which is OpenSSL's default
    places - the system's list on a Python of the distribution. A Python built with an OpenSSL
    of its own may look where there is nothing: then every connection that checks a certificate
    failed - and the system's trusted roots never reached acme. Pointed at the system's list
    then, and only then; a SSL_CERT_FILE or SSL_CERT_DIR given stays as given."""
    if os.environ.get('SSL_CERT_FILE') or os.environ.get('SSL_CERT_DIR'):
        return
    try:
        p = ssl.get_default_verify_paths()
    except Exception:                                   # noqa: BLE001
        return
    if p.cafile and os.path.isfile(p.cafile):
        return
    try:
        if p.capath and os.path.isdir(p.capath) and any(
                n.endswith('.0') for n in os.listdir(p.capath)):
            return
    except OSError:
        pass
    for f in OSR_SYSTEM_BUNDLES:
        if os.path.isfile(f):
            os.environ['SSL_CERT_FILE'] = f
            OSR_PY['fixed'] = f
            return


osr_python_fix()


def osr_python_trust():
    """Where acme's own connections look for the authorities they trust, and whether that is
    the system's list - the one these additions go into."""
    try:
        p = ssl.get_default_verify_paths()
    except Exception:                                   # noqa: BLE001
        return {}
    cafile = os.environ.get('SSL_CERT_FILE') or p.cafile or ''
    capath = os.environ.get('SSL_CERT_DIR') or p.capath or ''
    sysf = [f for f in OSR_SYSTEM_BUNDLES if os.path.isfile(f)]
    real = os.path.realpath(cafile) if cafile and os.path.isfile(cafile) else ''
    system = bool(real and any(os.path.realpath(f) == real for f in sysf)) or \
        bool(capath and os.path.isdir(capath) and
             os.path.realpath(capath) in ('/etc/ssl/certs', '/etc/pki/tls/certs'))
    return {'cafile': cafile, 'capath': capath, 'system': system, 'fixed': OSR_PY['fixed'],
            'openssl': getattr(ssl, 'OPENSSL_VERSION', '')}


# -- a certificate read (the same words as acme_web.py's osroots_facts) -------------------
def osr_blocks(text):
    """Each certificate of a text as (pem, der); a private key, or no certificate, refused."""
    text = str(text or '')
    if re.search(r'PRIVATE KEY|BEGIN ENCRYPTED|BEGIN PKCS7|BEGIN TRUSTED CERTIFICATE', text):
        raise ValueError('no private key and nothing but certificates (-----BEGIN CERTIFICATE-----)')
    out = []
    for body in OSR_BLOCK_RE.findall(text):
        try:
            der = base64.b64decode(re.sub(r'\s+', '', body), validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('a certificate that is not base64')
        if not der or len(der) > OSR_PEM_MAX * 3 // 4:
            raise ValueError('a certificate of %d bytes - one is a few kB at most' % len(der))
        enc = base64.b64encode(der).decode('ascii')
        out.append(('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % '\n'.join(
            enc[i:i + 64] for i in range(0, len(enc), 64)), der))
    if not out:
        raise ValueError('no certificate in it (-----BEGIN CERTIFICATE-----)')
    return out


def osr_text(raw):
    """A file as it came - PEM, or one certificate in DER (.cer) - as PEM text."""
    if isinstance(raw, str):
        raw = raw.encode('utf-8', 'replace')
    if b'-----BEGIN' in raw:
        return raw.decode('ascii', 'replace')
    if raw[:1] == b'\x30':
        try:
            return _openssl(['x509', '-inform', 'DER'], data=raw,
                            what='not a certificate in DER').decode('ascii')
        except (ValueError, OSError, subprocess.SubprocessError):
            pass
    raise ValueError('neither PEM (-----BEGIN CERTIFICATE-----) nor one certificate in DER')


def _osr_time(s):
    try:
        return calendar.timegm(time.strptime(re.sub(r'\s+', ' ', s.strip()), '%b %d %H:%M:%S %Y %Z'))
    except ValueError:
        return 0


def osr_facts(pem, der):
    """As the root helper reads it (acme_web.py osroots_facts - the same words): the names, the
    time, the key, whether it is an authority; `refused` what stands against it, `warn` what is
    to be known."""
    txt = _openssl(['x509', '-noout', '-text', '-nameopt', 'RFC2253'], data=pem.encode('ascii'),
                   what='not a certificate openssl reads').decode('utf-8', 'replace')

    def one(rx):
        m = re.search(rx, txt, re.M)
        return m.group(1).strip() if m else ''
    f = {'fp': hashlib.sha256(der).hexdigest(), 'subject': one(r'^\s*Subject: ?(.*)$')[:400],
         'issuer': one(r'^\s*Issuer: ?(.*)$')[:400],
         'not_before': _osr_time(one(r'Not Before\s*: (.*)$')),
         'not_after': _osr_time(one(r'Not After\s*: (.*)$')),
         'sig': one(r'Signature Algorithm: (\S+)')[:60]}
    cn = re.search(r'(?:^|,)CN=((?:\\.|[^,])*)', f['subject'])
    f['cn'] = (cn.group(1) if cn else f['subject'])[:200]
    alg = one(r'Public Key Algorithm: (\S+)')
    bits = one(r'Public-Key: \((\d+) bit\)')
    curve = one(r'NIST CURVE: (\S+)') or one(r'ASN1 OID: (\S+)')
    f['key'] = ('RSA %s' % bits) if alg == 'rsaEncryption' else \
        ('EC %s' % (curve or bits)) if alg == 'id-ecPublicKey' else \
        (alg.replace('ED25519', 'Ed25519').replace('ED448', 'Ed448')[:40] if alg else '?')
    f['bits'] = int(bits) if bits.isdigit() else 0
    bc = re.search(r'X509v3 Basic Constraints:.*\n\s*(CA:(TRUE|FALSE))', txt)
    f['ca'] = bool(bc and bc.group(2) == 'TRUE')
    ku = re.search(r'X509v3 Key Usage:.*\n\s*(.*)', txt)
    f['ku_sign'] = None if not ku else ('Certificate Sign' in ku.group(1))
    f['root'] = f['subject'] == f['issuer']
    f['kind'] = 'root' if f['root'] else 'intermediate'
    refused, warn = [], []
    now = time.time()
    if not bc:
        refused.append('it says nothing of being an authority (no basicConstraints CA:TRUE) - '
                       'only a certificate authority goes here')
    elif not f['ca']:
        refused.append('it is not a certificate authority (CA:FALSE) - a server\'s own certificate '
                       'does not go here')
    if f['ku_sign'] is False:
        refused.append('its key usage does not let it sign certificates (no keyCertSign)')
    if f['not_after'] and f['not_after'] < now:
        warn.append('it ran out on %s - nothing it signed is trusted' % time.strftime(
            '%Y-%m-%d', time.gmtime(f['not_after'])))
    if f['not_before'] and f['not_before'] > now + 300:
        warn.append('it is valid only from %s' % time.strftime('%Y-%m-%d', time.gmtime(f['not_before'])))
    if not f['root'] and re.search(r'(?i)(sha1|md5|md2)', f['sig']):         # ecdsa-with-SHA1 too
        warn.append('it is signed with %s - the system\'s crypto policy (DEFAULT) refuses it, and '
                    'every chain through it' % f['sig'])
    if f['key'].startswith('RSA') and 0 < f['bits'] < 2048:
        warn.append('its key has %d bits - the system\'s crypto policy (DEFAULT) refuses fewer '
                    'than 2048' % f['bits'])
    f['refused'], f['warn'] = refused, warn
    return f


# -- the set wanted ----------------------------------------------------------------------
def osr_hash(certs):
    return hashlib.sha256(','.join(sorted(str(c.get('fp') or '') for c in certs or [])).encode()).hexdigest()[:24]


def osr_rows(store, head):
    """Rows of meta beginning with head - those the database guard leaves out not among them."""
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (head + '%',))
    except Exception:                                   # noqa: BLE001
        return []
    return [r for r in dbguard_rows(store.db, rows) if str(r['k']).startswith(head)]


def osr_want(store):
    """The set wanted of the cluster - the newest of every node's row - or None while none was
    ever written (or none is acme's own: the guard leaves out a row written by somebody else)."""
    best = None
    for r in osr_rows(store, 'oscerts:want:'):
        got = _osr_obj(r['v'])
        if not got or not isinstance(got.get('certs'), list):
            continue
        try:
            v = int(got.get('v') or 0)
        except (TypeError, ValueError):
            continue
        key = (v, str(r['k']))
        if best is None or key > best[0]:
            best = (key, got, str(r['k'])[len('oscerts:want:'):])
    if best is None:
        return None
    got = best[1]
    certs = [c for c in got['certs'] if isinstance(c, dict) and isinstance(c.get('pem'), str)
             and re.match(r'^[0-9a-f]{64}\Z', str(c.get('fp') or ''))][:OSR_MAX]
    return {'v': best[0][0], 'certs': certs, 'by': str(got.get('by') or ''), 'at': _osr_num(got.get('at')),
            'node': best[2], 'what': str(got.get('what') or ''), 'hash': osr_hash(certs)}


def osr_save(store, certs, by, what):
    """A new set: this node's own row, its v above every v seen."""
    vs = [0]
    for r in osr_rows(store, 'oscerts:want:'):
        try:
            vs.append(int((_osr_obj(r['v']) or {}).get('v') or 0))
        except (TypeError, ValueError):
            continue
    v = max(int(time.time() * 1000), max(vs) + 1)
    row = {'v': v, 'certs': certs, 'by': by, 'at': time.time(), 'what': what}
    store.set_meta('oscerts:want:' + node_name(), json.dumps(row))
    store.add_event('settings', '%s %s - the system\'s trusted roots of every node' % (by, what),
                    'warn', who=by)
    return row


def osr_read_text(text):
    """Every certificate of a text (one, or a chain file of several), read: [facts with pem]."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError('the certificates: PEM text, or a file')
    if len(text) > OSR_MAX * OSR_PEM_MAX:
        raise ValueError('that is far more than %d certificates' % OSR_MAX)
    blocks = osr_blocks(osr_text(text))
    if len(blocks) > OSR_MAX:
        raise ValueError('%d certificates in it - %d at most' % (len(blocks), OSR_MAX))
    return [dict(osr_facts(pem, der), pem=pem) for pem, der in blocks]


def osr_check(store, text):
    """What adding this text would do - nothing written."""
    want = osr_want(store) or {'certs': []}
    have = {c['fp'] for c in want['certs']}
    subjects = {osr_facts_kept(c['pem']).get('subject') for c in want['certs']}
    got = osr_read_text(text)
    subjects |= {f['subject'] for f in got if not f['refused']}
    for f in got:
        f['already'] = f['fp'] in have
        # An intermediate whose root is nowhere here: trusted by itself only where a partial
        # chain is taken (curl, Python 3.13 on) - most other programs want its root too.
        if not f['root'] and not f['refused'] and f['issuer'] not in subjects:
            f['warn'] = f['warn'] + ['an intermediate without its root here: programs that take '
                                     'a partial chain (curl, Python 3.13 on) trust it by itself, '
                                     'others want its root too - add the root as well, unless '
                                     'the system\'s list has it']
    return got


def osr_add(store, text, by):
    got = osr_check(store, text)
    want = osr_want(store) or {'certs': []}
    certs = list(want['certs'])
    added, seen = [], set()
    for f in got:
        if not f['refused'] and not f['already'] and f['fp'] not in seen:
            seen.add(f['fp'])
            added.append(f)
    refused = [{'cn': f['cn'], 'fp': f['fp'], 'why': '; '.join(f['refused'])} for f in got if f['refused']]
    if not added:
        if refused:
            raise ValueError('nothing added: %s' % '; '.join('%s - %s' % (r['cn'], r['why']) for r in refused))
        raise ValueError('nothing added: every certificate in it is there already')
    if len(certs) + len(added) > OSR_MAX:
        raise ValueError('%d certificates at most - %d are there, %d more asked' % (
            OSR_MAX, len(certs), len(added)))
    for f in added:
        certs.append({'pem': f['pem'], 'fp': f['fp'], 'cn': f['cn'], 'kind': f['kind'],
                      'by': by, 'at': time.time()})
    osr_save(store, certs, by, 'added %s' % ', '.join(
        '%s (%s, SHA-256 %s)' % (f['cn'], f['kind'], f['fp'][:16]) for f in added))
    return {'added': [{k: f[k] for k in ('cn', 'fp', 'kind', 'warn')} for f in added],
            'refused': refused, 'already': [f['cn'] for f in got if f['already']],
            'message': ('added 1 - every node puts it into its system\'s trust within a minute'
                        if len(added) == 1 else
                        'added %d - every node puts them into its system\'s trust within a minute'
                        % len(added))}


def osr_find(certs, fp):
    fp = re.sub(r'[^0-9a-f]', '', str(fp or '').lower())
    if len(fp) < 12:
        raise ValueError('the SHA-256 fingerprint - 12 characters of it at least')
    hit = [c for c in certs if c['fp'].startswith(fp)]
    if not hit:
        raise ValueError('acme has added no certificate with that fingerprint')
    if len(hit) > 1:
        raise ValueError('more than one certificate begins with that - give more of it')
    return hit[0]


def osr_remove(store, fp, by):
    want = osr_want(store) or {'certs': []}
    c = osr_find(want['certs'], fp)
    certs = [x for x in want['certs'] if x['fp'] != c['fp']]
    osr_save(store, certs, by, 'took away %s (SHA-256 %s)' % (c.get('cn') or '?', c['fp'][:16]))
    return {'message': 'taken away - every node takes it out of its system\'s trust within a minute'}


def osr_again(store, by=''):
    store.set_meta('oscerts:again:' + node_name(), repr(time.time()))
    if by:
        store.add_event('settings', '%s asked every node to read the system\'s trusted roots again'
                        % by, 'info', who=by)


# -- each node ---------------------------------------------------------------------------
def _osr_state(data):
    """What the helper said of the machine, as it is kept: without the PEMs."""
    keep = {}
    for k in ('ours', 'others', 'system', 'flavour', 'dir', 'tool', 'tool_there'):
        if k in data:
            keep[k] = data[k]
    keep['ours'] = [x for x in (keep.get('ours') or []) if isinstance(x, dict)][:OSR_MAX + 10]
    keep['others'] = [x for x in (keep.get('others') or []) if isinstance(x, dict)][:200]
    if not isinstance(keep.get('system'), dict):
        keep['system'] = {}
    return keep


def osroots_tick(daemon):
    """Every few seconds: is this node's machine to be brought to the set (or only read)? The
    work in a thread, one at a time."""
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    store = daemon.store
    with OSR_LOCK:
        if OSR['busy'] and time.time() - OSR['since'] < OSR_STALE_S:
            return
    want = osr_want(store)
    h = want['hash'] if want else None
    again = ''
    for r in osr_rows(store, 'oscerts:again:'):
        again = max(again, str(r['v'] or ''))
    now = time.time()
    due = now - OSR['done_at'] > OSR_RESYNC_S
    if want is not None and h != OSR['done_hash'] and \
            not (h == OSR['fail_hash'] and now - OSR['fail_at'] < OSR_RETRY_S):
        due = True
    if again != OSR['again_seen']:
        first = OSR['again_seen'] is None
        OSR['again_seen'] = again
        if again and not first:
            due = True
    if not due:
        return
    with OSR_LOCK:
        if OSR['busy'] and time.time() - OSR['since'] < OSR_STALE_S:
            return
        OSR['busy'], OSR['since'] = True, time.time()
    threading.Thread(target=osroots_run, args=(store, want), name='acme-osroots', daemon=True).start()


def osroots_run(store, want):
    """This node's root helper asked: the set put in (or the machine only read) - and how it
    went written to this node's own row."""
    me = node_name()
    h = want['hash'] if want else None
    row = {'at': time.time(), 'v': want['v'] if want else 0, 'hash': h or '', 'ok': False,
           'error': '', 'said': [], 'refused': [], 'python': osr_python_trust()}
    old = _meta_obj(store, 'oscerts:node:' + me)
    try:
        try:
            if want is None:
                data = root_ask('osroots.ask', 'osroots.json', {'do': 'list'}, 120)
            else:
                data = root_ask('osroots.ask', 'osroots.json',
                                {'do': 'sync', 'certs': [c['pem'] for c in want['certs']]}, 300)
            if not isinstance(data, dict):
                raise ValueError('the root helper of this node answered osroots.ask with no object - '
                                 'is it of the same version as acme?')
            row.update(ok=True, said=[str(x)[:200] for x in data.get('said') or []][:120],
                       refused=[x for x in data.get('refused') or [] if isinstance(x, dict)][:OSR_MAX],
                       state=_osr_state(data))
            OSR.update(done_hash=h, done_at=time.time(), fail_hash=None)
            if row['said']:
                log('the system\'s trusted roots: %s' % '; '.join(row['said']))
                store.add_event('settings', '%s: the system\'s trusted roots - %s' % (
                    me, '; '.join(row['said'])), 'info')
            if row['refused']:
                store.add_event('settings', '%s: the system\'s trusted roots - not taken: %s' % (
                    me, '; '.join('%s - %s' % (x.get('cn') or '?', x.get('why') or '?')
                                  for x in row['refused'])), 'bad')
        except Exception as e:                          # noqa: BLE001
            row.update(error=str(e)[:400] or e.__class__.__name__, state=old.get('state') or {})
            OSR.update(done_hash=None, done_at=time.time(), fail_hash=h, fail_at=time.time())
            # Only read (nothing of acme's wanted): said quietly - a node whose helper is of a
            # version before (an upgrade under way) has nothing to put in anyway.
            log_sparing('osroots', 'the system\'s trusted roots: %s' % e, 'warn' if want else 'info',
                        every=900 if want else 3600)
            if want is not None and old.get('error') != row['error']:
                store.add_event('settings', '%s: the system\'s trusted roots - %s' % (me, row['error']),
                                'bad')
        try:
            store.set_meta('oscerts:node:' + me, json.dumps(row))
        except Exception as e:                          # noqa: BLE001
            log_sparing('osroots-row', 'the system\'s trusted roots: %s' % e, 'warn', every=900)
    finally:
        with OSR_LOCK:
            OSR['busy'] = False


def osr_node_status(want, row, alive):
    """(status, words): applied, waiting, failed - or 'none' while nothing was ever asked."""
    if want is None:
        if row.get('error'):
            return 'failed', str(row['error'])
        return 'none', ''
    if row.get('at') and row.get('hash') == want['hash']:
        if not row.get('ok'):
            return 'failed', str(row.get('error') or 'the root helper said no')
        if row.get('refused'):
            return 'failed', '; '.join('%s - %s' % (r.get('cn') or '?', r.get('why') or '?')
                                       for r in row['refused'])
        return 'applied', ''
    if not alive:
        return 'waiting', 'not answering'
    if time.time() - _osr_num(want.get('at')) > OSR_LATE_S:
        return 'waiting', ('asked more than five minutes ago and not done - is it of this version, '
                           'and is acme-web.path running there?') + (
                               (' (last: %s)' % row['error']) if row.get('error') else '')
    return 'waiting', ''


OSR_FACTS = {}


def osr_facts_kept(pem):
    """A certificate of the set read once (the view is asked every few seconds)."""
    key = hashlib.sha256(pem.encode('utf-8', 'replace')).hexdigest()
    got = OSR_FACTS.get(key)
    if got is None:
        try:
            p, der = osr_blocks(pem)[0]
            got = osr_facts(p, der)
        except (ValueError, OSError, subprocess.SubprocessError) as e:
            got = {'cn': '?', 'warn': [], 'refused': [str(e)]}
        if len(OSR_FACTS) > 400:
            OSR_FACTS.clear()
        OSR_FACTS[key] = got
    return got


def osr_view(store):
    want = osr_want(store)
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        row = _meta_obj(store, 'oscerts:node:' + n)
        status, why = osr_node_status(want, row, alive.get(n, False))
        st = row.get('state') if isinstance(row.get('state'), dict) else {}
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'status': status, 'why': why, 'at': row.get('at'), 'said': row.get('said') or [],
                      'error': row.get('error') or '', 'ours': st.get('ours') or [],
                      'others': st.get('others') or [], 'system': st.get('system') or {},
                      'flavour': st.get('flavour') or '', 'dir': st.get('dir') or '',
                      'tool': st.get('tool') or '', 'tool_there': st.get('tool_there'),
                      'python': row.get('python') or {}})
    certs = []
    facts = [(c, osr_facts_kept(c['pem'])) for c in (want or {}).get('certs') or []]
    subjects = {f.get('subject') for _c, f in facts}
    for c, f in facts:
        warn = list(f.get('warn') or [])
        if f.get('kind') == 'intermediate' and f.get('issuer') not in subjects:
            warn.append('its root is not among these - trusted by itself only where a partial chain '
                        'is taken (curl, Python 3.13 on), unless the system\'s list has the root')
        on = {}
        for n in nodes:
            hit = [x for x in n['ours'] if isinstance(x, dict) and x.get('fp') == c['fp']]
            on[n['name']] = (hit[0].get('in_bundle') is not False) if hit else False
        certs.append({'fp': c['fp'], 'pem': c['pem'], 'cn': f.get('cn'), 'subject': f.get('subject'),
                      'issuer': f.get('issuer'), 'not_before': f.get('not_before'),
                      'not_after': f.get('not_after'), 'key': f.get('key'), 'kind': f.get('kind'),
                      'sig': f.get('sig'), 'warn': warn, 'by': c.get('by') or '',
                      'at': c.get('at'), 'on': on})
    return {'certs': certs, 'nodes': nodes, 'cluster': len(nodes) > 1, 'max': OSR_MAX,
            'want': {k: want[k] for k in ('v', 'by', 'at', 'node', 'what', 'hash')} if want else None,
            'python': osr_python_trust()}


@route('GET', '/api/osroots')
def _osroots(h):
    h.me()          # read-only may see: certificates of authorities are nothing secret
    return osr_view(h.store)


@route('POST', '/api/osroots')
def _osroots_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'check':
            got = osr_check(h.store, b.get('text'))
            return {'certs': [{k: f[k] for k in ('fp', 'cn', 'subject', 'issuer', 'not_before', 'not_after',
                                                   'key', 'kind', 'sig', 'warn', 'refused', 'already')}
                              for f in got]}
        if act == 'add':
            return osr_add(h.store, b.get('text'), s['name'])
        if act == 'remove':
            return osr_remove(h.store, b.get('fp'), s['name'])
        if act == 'refresh':
            osr_again(h.store, s['name'])
            return {'message': 'asked: every node reads its trusted roots again within a minute'}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'check, add, remove or refresh')
