# -*- coding: utf-8 -*-
"""
acme's side of acme-agent (1.0.116, docs/target-agent.md): a target that holds none of the
server's credentials. A small agent on the server (deploy/agent/acme_agent.py) does what its
own policy allows; acme proposes, signed.

What acme keeps (all in meta, so in every backup, on every node of a cluster):

    agents:ca          acme's agent authority: its certificate and key (sealed) - it signs the
                       agents' certificates (30 days) and acme's own (CN acme-agents)
    agents:cmd         acme's command key (Ed25519, sealed): every job is signed with it; the
                       agent pins its public half at the join
    agents:ctl         acme's own certificate of the authority (CN acme-agents): the client
                       certificate of a passive call, the server certificate of the agents port
    agents:t:<id>      one target's agent: its mode, id, state of the join, the fingerprints of
                       its certificate, its X25519 key (public), what it last said (version,
                       policy), when it was last heard from
    agents:id:<agent>  which target an agent id is
    agentq:<id>:<job>  a job for an active agent, waiting for its poll (either node serves it)
    agentr:<job>       its result

Nothing the agent sends is believed but what it may say: sizes and shapes are checked, every
word of it is text shown as text.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from acmelib import engine as E
from acmelib.plugins.base import PluginError

PROTO = 'acme-agent/1'
CODE_S = 3600                   # a join code: one hour, once
CODE_TRIES = 5
CERT_DAYS = 30
RENEW_DAYS = 10
CTL_DAYS = 730
CTL_RENEW_DAYS = 60
CA_DAYS = 3650
CTL_CN = 'acme-agents'
AGENT_CN = 'acme-agent:'
PASSIVE_PORT = 8446
ACTIVE_PORT = 8444
QUIET_S = 600                   # an agent not heard from this long: said (an alert, an event)
HELLO_EVERY_S = 300             # a passive agent asked how it is this often (the leader)
HOLD_S = 20                     # a poll held this long at most while there is nothing to do
HOLD_MOST = 3                   # polls held at once on a node (php-fpm has 12 children)
TAKE_S = 90                     # a job no active agent took in this long fails
BODY_MOST = 4 * 1024 * 1024
SEAL_ALG = 'X25519-HKDF-SHA256-A256GCM'
AGENT_ID_RE = re.compile(r'ag-[0-9a-f]{12,32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
LOCK = threading.RLock()
HOLDING = {'n': 0}
BUSY = set()                    # targets whose certificate is being renewed (this node)

M_CA, M_CMD, M_CTL = 'agents:ca', 'agents:cmd', 'agents:ctl'


def M_T(tid):
    return 'agents:t:%d' % int(tid)


def M_ID(aid):
    return 'agents:id:%s' % aid


# ---- the agent's own program: its policy logic is the very one acme reasons with ----------------
AGENT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'deploy', 'agent')
_AGENT = {}


def agent_mod():
    """deploy/agent/acme_agent.py, loaded once: its policy checks (plan_check) tell the pages
    what a deployment needs before it runs - the same code the agent runs."""
    if 'm' not in _AGENT:
        spec = importlib.util.spec_from_file_location('acme_agent_program',
                                                      os.path.join(AGENT_DIR, 'acme_agent.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _AGENT['m'] = m
    return _AGENT['m']


# ---- small things -----------------------------------------------------------------------------
def _jload(text, default):
    try:
        got = json.loads(text) if text else None
    except (TypeError, ValueError):
        got = None
    return got if got is not None else default


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def _openssl(args, data=None):
    got = subprocess.run(['openssl'] + args, input=data, capture_output=True, text=True,
                         timeout=60)
    if got.returncode != 0:
        raise PluginError('openssl: %s' % (got.stderr or got.stdout).strip()[-200:], retry=False)
    return got.stdout


def fp_of_pem(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(str(pem).strip() + '\n')).hexdigest()


def spki_fp(pem):
    """sha256 of the public key (SubjectPublicKeyInfo DER) of a key, a certificate or a CSR - the
    fingerprint the agent prints and the person confirms."""
    text = str(pem or '')
    if 'CERTIFICATE REQUEST' in text:
        pub = _openssl(['req', '-noout', '-pubkey'], text)
    elif 'CERTIFICATE' in text:
        pub = _openssl(['x509', '-noout', '-pubkey'], text)
    else:
        pub = _openssl(['pkey', '-pubout'], text)
    got = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub.encode(),
                         capture_output=True, timeout=30)
    if got.returncode != 0:
        raise PluginError('not a public key', retry=False)
    return hashlib.sha256(got.stdout).hexdigest()


def fp_words(fp):
    fp = str(fp or '').upper()
    return ' '.join(fp[i:i + 4] for i in range(0, len(fp), 4))


_ENDS = {}


def cert_end(pem):
    pem = str(pem)
    if pem in _ENDS:
        return _ENDS[pem]
    out = _openssl(['x509', '-noout', '-enddate'], pem)
    end = float(ssl.cert_time_to_seconds(out.strip().split('=', 1)[-1]))
    if len(_ENDS) > 512:
        _ENDS.clear()
    _ENDS[pem] = end
    return end


def _when(ts):
    try:
        return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(ts))) if ts else '-'
    except (TypeError, ValueError):
        return '-'


def _txt(v, most=300):
    """Words of the agent's, as words: no control characters, cut."""
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(v if v is not None else ''))[:most]


# ---- acme's keys: the authority, the command key, its own certificate -----------------------------
def ca(store):
    """{cert_pem, key_pem, fp} - made the first time it is needed, kept sealed."""
    with LOCK:
        got = E._meta_obj(store, M_CA)
        if got.get('cert') and got.get('key'):
            key = E.unseal_secret(got['key'], M_CA)
            if key:
                return {'cert_pem': got['cert'], 'key_pem': key, 'fp': got.get('fp') or
                        fp_of_pem(got['cert'])}
            raise PluginError('the agent authority\'s key does not open on this node (the '
                              'sealing key is not the one it was sealed with)', retry=False)
        with tempfile.TemporaryDirectory() as t:
            k = os.path.join(t, 'k.pem')
            _openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                      '-out', k])
            site = re.sub(r'[^A-Za-z0-9 ._-]', '', str(E.CONFIG.get('site_name') or 'acme'))[:40]
            pem = _openssl(['req', '-x509', '-new', '-key', k, '-days', str(CA_DAYS), '-subj',
                            '/CN=%s agent authority/O=acme' % (site or 'acme'),
                            '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                            '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
            with open(k) as f:
                kpem = f.read()
        store.set_meta(M_CA, json.dumps({'cert': pem, 'key': E.seal_secret(kpem, M_CA),
                                         'fp': fp_of_pem(pem), 'at': time.time()}))
        store.add_event('certificates', 'the agent authority was made (target agents): SHA-256 %s'
                        % fp_of_pem(pem))
        return {'cert_pem': pem, 'key_pem': kpem, 'fp': fp_of_pem(pem)}


def ca_public(store):
    got = E._meta_obj(store, M_CA)
    if not got.get('cert'):
        return None
    try:
        return {'fp': got.get('fp') or fp_of_pem(got['cert']), 'end': cert_end(got['cert']),
                'at': got.get('at')}
    except PluginError:
        return None


def cmd_key(store):
    """acme's command key: {'seed', 'public', 'fp'} (Ed25519, sealed)."""
    with LOCK:
        got = E._meta_obj(store, M_CMD)
        seed = None
        if got.get('seed'):
            plain = E.unseal_secret(got['seed'], M_CMD)
            if plain:
                seed = base64.b64decode(plain)
        if not seed:
            if got.get('seed'):
                raise PluginError('acme\'s command key does not open on this node', retry=False)
            seed = secrets.token_bytes(32)
            store.set_meta(M_CMD, json.dumps({'seed': E.seal_secret(_b64(seed), M_CMD),
                                              'at': time.time()}))
    pub = E.ed25519_public(seed)
    return {'seed': seed, 'public': pub, 'fp': hashlib.sha256(pub).hexdigest()}


def sign_csr(store, csr_pem, cn, days, server=True):
    """A certificate of the agent authority for a CSR (the key checked: P-256/P-384, Ed25519 or
    RSA of 2048 bits or more; its own signature checked)."""
    a = ca(store)
    csr = str(csr_pem or '')
    if not re.match(r'\s*-----BEGIN CERTIFICATE REQUEST-----', csr) or len(csr) > 8192:
        raise PluginError('not a certificate request', retry=False)
    _openssl(['req', '-noout', '-verify'], csr)
    txt = _openssl(['req', '-noout', '-text'], csr)
    if not re.search(r'(NIST CURVE: P-(256|384)|ED25519|Public-Key: \((2048|3072|4096) bit\))',
                     txt, re.I):
        raise PluginError('the agent\'s key is ECDSA P-256 / P-384, Ed25519 or RSA of 2048 bits '
                          'or more', retry=False)
    with tempfile.TemporaryDirectory() as t:
        j = lambda n: os.path.join(t, n)  # noqa: E731
        for n, v in (('c.pem', a['cert_pem']), ('k.pem', a['key_pem']), ('r.csr', csr)):
            with open(j(n), 'w') as f:
                f.write(v)
        os.chmod(j('k.pem'), 0o600)
        with open(j('ext'), 'w') as f:
            f.write('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                    'extendedKeyUsage=%s\n' % ('serverAuth,clientAuth' if server else
                                               'clientAuth'))
        return _openssl(['x509', '-req', '-in', j('r.csr'), '-CA', j('c.pem'), '-CAkey',
                         j('k.pem'), '-set_serial', '0x' + secrets.token_hex(12), '-days',
                         str(days), '-extfile', j('ext'), '-subj', '/CN=%s' % cn])


def ctl(store):
    """acme's own certificate of the authority (CN acme-agents): {cert_pem, key_pem, fp, end} -
    made again 60 days before its end (the agents trust the authority, not it)."""
    with LOCK:
        got = E._meta_obj(store, M_CTL)
        if got.get('cert') and got.get('key'):
            key = E.unseal_secret(got['key'], M_CTL)
            try:
                end = cert_end(got['cert'])
            except PluginError:
                end = 0
            if key and end - time.time() > CTL_RENEW_DAYS * 86400 and \
                    got.get('ca') == ca(store)['fp']:
                return {'cert_pem': got['cert'], 'key_pem': key, 'fp': fp_of_pem(got['cert']),
                        'end': end}
        with tempfile.TemporaryDirectory() as t:
            k = os.path.join(t, 'k.pem')
            _openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                      '-out', k])
            csr = _openssl(['req', '-new', '-key', k, '-subj', '/CN=%s' % CTL_CN])
            with open(k) as f:
                kpem = f.read()
        pem = sign_csr(store, csr, CTL_CN, CTL_DAYS)
        store.set_meta(M_CTL, json.dumps({'cert': pem, 'key': E.seal_secret(kpem, M_CTL),
                                          'ca': ca(store)['fp'], 'at': time.time()}))
        return {'cert_pem': pem, 'key_pem': kpem, 'fp': fp_of_pem(pem), 'end': cert_end(pem)}


# ---- sealing and signing ----------------------------------------------------------------------
def seal(enc_pub_b64, agent_id, label, data):
    """`data` (bytes) sealed to the agent's X25519 key for `label` - the scheme of acme push
    (docs/acme-push-protocol.md section 7) with info and aad of acme-agent's own."""
    app_pub = base64.b64decode(str(enc_pub_b64 or ''))
    if len(app_pub) != 32:
        raise PluginError('the agent has no key to seal to (join it again)', retry=False)
    eph = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    epk = E.x25519_public(eph)
    shared = E.x25519(eph, app_pub)
    if shared == bytes(32):
        raise PluginError('the agent\'s key is not one to seal to', retry=False)
    k = E.hkdf_sha256(shared, epk + app_pub, ('%s seal' % PROTO).encode())
    aad = ('%s seal\n%s\n%s' % (PROTO, agent_id, label)).encode('utf-8')
    return {'alg': SEAL_ALG, 'epk': _b64(epk), 'nonce': _b64(nonce),
            'ct': _b64(E.aes256gcm(k, nonce, bytes(data), aad))}


def sign_job(store, agent_id, op, args):
    """(job id, {'job': text, 'sig': base64}) - signed with acme's command key."""
    jid = secrets.token_hex(12)
    body = json.dumps({'v': 1, 'agent': agent_id, 'job': jid, 'ts': int(time.time()),
                       'nonce': secrets.token_hex(16), 'op': op, 'args': args or {}},
                      sort_keys=True, separators=(',', ':'))
    sig = E.ed25519_sign(cmd_key(store)['seed'], ('%s job\n' % PROTO).encode() +
                         body.encode('utf-8'))
    return jid, {'job': body, 'sig': _b64(sig)}


def proof(secret, *parts):
    msg = '\n'.join([PROTO] + [str(p) for p in parts]).encode('utf-8')
    return hmac.new(str(secret).encode('utf-8'), msg, hashlib.sha256).hexdigest()


# ---- one target's agent -----------------------------------------------------------------------
def state(store, tid):
    return E._meta_obj(store, M_T(tid))


def state_put(store, tid, st):
    store.set_meta(M_T(tid), json.dumps(st, sort_keys=True))


def target_row(store, ref):
    from acmelib.certs import store as S
    row = S.plugin_row(store, 'target', ref)
    if not row or row.get('kind') != 'agent':
        raise LookupError('there is no target with acme-agent of that name')
    return row


def target_conf(row):
    from acmelib.certs import store as S
    return S.plugin_config('target', row)


def mode_of(row):
    m = str(target_conf(row).get('mode') or 'passive')
    return m if m in ('passive', 'active') else 'passive'


def active_on():
    try:
        return bool(int(E.CONFIG.get('certs_agents_active') or 0))
    except (TypeError, ValueError):
        return False


def active_port():
    try:
        p = int(E.CONFIG.get('certs_agents_port') or ACTIVE_PORT)
    except (TypeError, ValueError):
        p = ACTIVE_PORT
    return p if 1024 <= p <= 65535 else ACTIVE_PORT


def endpoints(store):
    """Where an active agent finds acme: the addresses set on the pane, else the VIP address and
    each node's - the agent tries them in turn."""
    port = active_port()
    given = [x.strip() for x in re.split(r'[\s,]+', str(E.CONFIG.get('certs_agents_names') or ''))
             if x.strip()]
    hosts = []
    if given:
        hosts = given
    else:
        try:
            v = E.vip_conf(store) or {}
            if E.CONFIG.get('ha_mode') and v.get('on'):
                hosts.append(v.get('fqdn') or str(v.get('address') or '').split('/')[0])
        except Exception:                               # noqa: BLE001
            pass
        try:
            for n in E.ha_nodes(store) if E.CONFIG.get('ha_mode') else []:
                if n.get('address'):
                    hosts.append(str(n['address']).split('/')[0])
        except Exception:                               # noqa: BLE001
            pass
        if not hosts:
            name = str(E.CONFIG.get('acme_node_name') or '') or socket.getfqdn()
            hosts.append(name or str(E.node_address()))
    out = []
    for h in hosts:
        h = str(h).strip()
        if not h:
            continue
        if re.search(r':\d{1,5}\Z', h) and (h.count(':') == 1 or h.startswith('[')):
            hp = h
        elif ':' in h:
            hp = '[%s]:%d' % (h.strip('[]'), port)
        else:
            hp = '%s:%d' % (h, port)
        if hp not in out:
            out.append(hp)
    return out[:8]


def info(store, row, full=False):
    """What the pages show of one target's agent - never a secret."""
    st = state(store, row['id'])
    now = time.time()
    mode = mode_of(row)
    seen = float(st.get('last_seen') or 0)
    joined = bool(st.get('cert_fp'))
    if not joined:
        pill = 'joining' if st.get('code') or st.get('pending') else 'new'
    elif not (row.get('enabled') is None or int(row.get('enabled') or 0)):
        pill = 'off'
    elif st.get('refused'):
        pill = 'refused'
    elif seen and now - seen < QUIET_S:
        pill = 'answers'
    else:
        pill = 'quiet'
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    code = st.get('code') if isinstance(st.get('code'), dict) else {}
    pend = st.get('pending') if isinstance(st.get('pending'), dict) else {}
    out = {'id': row['id'], 'name': row['name'], 'mode': mode, 'state': pill,
           'agent_id': st.get('agent_id') or '', 'joined': joined,
           'host': target_conf(row).get('host') or st.get('host') or '',
           'version': st.get('version') or '', 'code_hash': st.get('code_hash') or '',
           'os': st.get('os') or '', 'agent_host': st.get('host') or '',
           'last_seen': seen or None, 'last_error': st.get('last_error') or '',
           'cert_end': st.get('cert_end'), 'cert_fp': st.get('cert_fp') or '',
           'key_fp': st.get('key_fp') or '', 'joined_at': st.get('joined_at'),
           'policy': pol, 'policy_at': st.get('policy_at'),
           'code_until': code.get('until') if code and not code.get('used') and
           float(code.get('until') or 0) > now else None,
           'pending': {'fp': pend.get('fp'), 'fp_words': fp_words(pend.get('fp')),
                       'at': pend.get('at'), 'host': pend.get('host') or '',
                       'version': pend.get('version') or '', 'confirmed': bool(pend.get('cert'))}
           if pend else None,
           'active_on': active_on(), 'enabled': row.get('enabled') is None or
           bool(int(row.get('enabled') or 0)), 'shipped_code': shipped_code()}
    out['policy_summary'] = policy_summary(pol)
    out['update'] = update_facts(st) if joined else None
    blk = st.get('blocked') if isinstance(st.get('blocked'), dict) else None
    out['blocked'] = {'at': blk.get('at'), 'what': blk.get('what') or '',
                      'allow': list(blk.get('allow') or [])} if blk else None
    out['via'] = str(target_conf(row).get('via') or '')
    # the certificates whose key its agent makes (phase 3)
    out['keys_of'] = [r['name'] for r in store.db.rows(
        'SELECT name FROM certs WHERE csr_from = ? ORDER BY name', (row['name'],))][:50]
    return out


def policy_summary(pol):
    if not isinstance(pol, dict):
        return None
    return {'files': len(pol.get('files') or []), 'units': len(pol.get('units') or {}),
            'tests': len(pol.get('tests') or []),
            'scripts': len(pol.get('scripts') or []) + len(pol.get('script_hashes') or []),
            'from': len(pol.get('from') or []), 'hash': str(pol.get('hash') or '')[:64],
            'problems': len(pol.get('problems') or []),
            'probes': len(pol.get('probe') or []) + (1 if pol.get('probe_local') else 0),
            'connects': len(pol.get('connect') or []),
            'self_update': bool(pol.get('self_update'))}


def shipped_code():
    try:
        return agent_mod().code_hash(AGENT_DIR)
    except Exception:                                   # noqa: BLE001
        return ''


# ---- the join ---------------------------------------------------------------------------------
def code_new(store, row, by):
    """A one-time join code (an hour, once) - a new agent id; the one joined until now stays
    until the new one is confirmed."""
    mode = mode_of(row)
    if mode == 'active' and not active_on():
        raise PluginError('the agents\' port is off: an active agent cannot reach acme - switch '
                          'it on at Settings → Target agents, or make the target passive',
                          retry=False)
    st = state(store, row['id'])
    a = ca(store)
    ck = cmd_key(store)
    ctl(store)
    cid = secrets.token_hex(6)
    secret = secrets.token_urlsafe(24)
    aid = 'ag-' + secrets.token_hex(8)
    until = time.time() + CODE_S
    st['code'] = {'id': cid, 'secret': E.seal_secret(secret, M_T(row['id']) + ':code'),
                  'until': until, 'agent_id': aid, 'mode': mode, 'tries': 0, 'by': by,
                  'at': time.time()}
    st.pop('pending', None)
    st['mode'] = mode
    state_put(store, row['id'], st)
    data = {'v': 1, 't': row['id'], 'n': row['name'], 'm': mode, 'i': cid, 's': secret,
            'ca': a['fp'], 'ck': ck['fp'], 'u': int(until)}
    if mode == 'active':
        data['a'] = endpoints(store)
    else:
        data['p'] = int(target_conf(row).get('port') or PASSIVE_PORT)
    code = 'ACAG1.' + base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':'))
                                               .encode()).decode().rstrip('=')
    store.add_event('certificates', 'a join code for the agent of target %s was made by %s '
                    '(%s, an hour, once)' % (row['name'], by, mode), who=by)
    return {'code': code, 'until': until, 'mode': mode, 'ca_fp': a['fp'],
            'endpoints': data.get('a') or [], 'port': data.get('p')}


def _code_of(store, cid):
    """(row, state, code, secret) of a code id - or LookupError."""
    if not re.fullmatch(r'[0-9a-f]{12}', str(cid or '')):
        raise LookupError('no such code')
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:t:%'"):
        st = _jload(r['v'], {})
        c = st.get('code') if isinstance(st, dict) else None
        if isinstance(c, dict) and c.get('id') == cid:
            tid = int(r['k'].rsplit(':', 1)[1])
            row = store.db.row('SELECT * FROM cert_targets WHERE id = ?', (tid,))
            if not row or row.get('kind') != 'agent':
                break
            secret = E.unseal_secret(c.get('secret'), M_T(tid) + ':code')
            if not secret:
                break
            return row, st, c, secret
    raise LookupError('no such code')


def _refuse(store, row, words):
    store.add_event('certificates', 'the agent of target %s: %s' % (row['name'], words), 'warn')


def join_take(store, row, st, c, secret, req, tls_key_fp=None):
    """The agent's join request (its CSR, its X25519 key, its proof of the code) - kept as
    pending until a person confirms its fingerprint."""
    now = time.time()
    if c.get('used') and (st.get('pending') or {}).get('csr') != req.get('csr'):
        raise PluginError('the join code was used already - make a new one', retry=False)
    if float(c.get('until') or 0) < now:
        raise PluginError('the join code ran out - make a new one', retry=False)
    if int(c.get('tries') or 0) >= CODE_TRIES:
        raise PluginError('the join code was tried too often - make a new one', retry=False)
    csr, enc = str(req.get('csr') or ''), str(req.get('enc_pub') or '')
    nonce = str(req.get('nonce') or '')
    want = proof(secret, 'join', c['id'], hashlib.sha256(csr.encode()).hexdigest(), enc, nonce)
    if not re.fullmatch(r'[0-9a-f]{32}', nonce) or \
            not hmac.compare_digest(want, str(req.get('proof') or '')):
        c['tries'] = int(c.get('tries') or 0) + 1
        st['code'] = c
        state_put(store, row['id'], st)
        _refuse(store, row, 'a join with a wrong code was refused')
        raise PluginError('the request does not prove the join code', retry=False)
    try:
        if len(base64.b64decode(enc)) != 32:
            raise ValueError
    except ValueError:
        raise PluginError('the agent sent no key to seal secrets to', retry=False)
    fp = spki_fp(csr)
    if tls_key_fp is not None and tls_key_fp != fp:
        raise PluginError('the agent answers with another key than it asks a certificate for',
                          retry=False)
    c['used'] = True
    st['code'] = c
    st['pending'] = {'csr': csr, 'fp': fp, 'enc_pub': enc, 'agent_id': c['agent_id'],
                     'version': _txt(req.get('version'), 40), 'code_hash': _txt(req.get('code'), 64),
                     'host': _txt(req.get('host'), 120), 'at': now, 'code_id': c['id']}
    state_put(store, row['id'], st)
    store.add_event('certificates', 'the agent of target %s asks to join (%s, key %s…) - its '
                    'fingerprint is confirmed on the target\'s card' % (
                        row['name'], st['pending']['host'] or '?', fp[:16]), 'info')
    return fp


def join_answer(store, secret, c, nonce):
    a = ca(store)
    ck = cmd_key(store)
    pub = _b64(ck['public'])
    return {'ok': True, 'agent_id': c['agent_id'], 'ca_pem': a['cert_pem'], 'cmd_pub': pub,
            'endpoints': endpoints(store) if c.get('mode') == 'active' else [],
            'proof': proof(secret, 'joined', c['id'], hashlib.sha256(a['cert_pem'].encode())
                           .hexdigest(), pub, c['agent_id'], nonce)}


def confirm(store, row, fp, by):
    """A person confirmed the fingerprint the agent printed: its certificate is signed (30 days),
    the agent id it joined with in force - the one before no longer let in."""
    st = state(store, row['id'])
    pend = st.get('pending') if isinstance(st.get('pending'), dict) else None
    if not pend:
        raise PluginError('no agent waits to be confirmed on this target', retry=False)
    given = re.sub(r'[^0-9a-f]', '', str(fp or '').lower())
    if not hmac.compare_digest(given, str(pend.get('fp') or '')):
        _refuse(store, row, 'a fingerprint that is not the agent\'s was given to confirm it')
        raise PluginError('that is not the fingerprint of the agent that asks - compare it with '
                          'what `acme-agent join` printed on the target', retry=False)
    aid = pend['agent_id']
    cert = sign_csr(store, pend['csr'], AGENT_CN + aid, CERT_DAYS)
    old = st.get('agent_id')
    pend['cert'] = cert
    pend['confirmed_by'] = by
    pend['confirmed_at'] = time.time()
    st['pending'] = pend
    _install_identity(store, row, st, pend, cert)
    store.add_event('certificates', 'the agent of target %s was confirmed by %s (key %s…) - its '
                    'certificate is valid until %s' % (row['name'], by, pend['fp'][:16],
                                                       _when(st.get('cert_end'))), who=by)
    if old and old != aid:
        store.db.run('DELETE FROM meta WHERE k = ?', (M_ID(old),))
    return st


def _install_identity(store, row, st, pend, cert):
    aid = pend['agent_id']
    st.update(agent_id=aid, cert_fp=fp_of_pem(cert), cert_prev_fp='', cert_end=cert_end(cert),
              key_fp=pend['fp'], enc_pub=pend['enc_pub'], version=pend.get('version') or '',
              code_hash=pend.get('code_hash') or '', host=pend.get('host') or '',
              joined_at=time.time(), refused='', last_error='', mode=mode_of(row))
    st['policy'] = None
    state_put(store, row['id'], st)
    store.set_meta(M_ID(aid), str(row['id']))


def finish_passive(store, row, st):
    """A passive agent confirmed: its certificate handed to it (acme reaches it)."""
    pend = st.get('pending') or {}
    if not pend.get('cert'):
        return False
    c = st.get('code') or {}
    secret = E.unseal_secret(c.get('secret'), M_T(row['id']) + ':code')
    if not secret:
        raise PluginError('the join code\'s secret is gone - make a new code', retry=False)
    nonce = secrets.token_hex(16)
    body = {'cert_pem': pend['cert'], 'nonce': nonce,
            'proof': proof(secret, 'cert', c['id'], hashlib.sha256(pend['cert'].encode())
                           .hexdigest(), nonce)}
    got, _peer = _passive_post(store, row, '/v1/join/finish', body, joining=pend['fp'])
    if not got.get('ok'):
        raise PluginError('the agent did not take its certificate: %s' % _txt(got.get('said')),
                          retry=True)
    _joined(store, row)
    return True


def _joined(store, row):
    st = state(store, row['id'])
    st.pop('pending', None)
    st.pop('code', None)
    st['last_seen'] = time.time()
    state_put(store, row['id'], st)
    store.add_event('certificates', 'the agent of target %s joined acme (%s) - %s' % (
        row['name'], st.get('agent_id'), st.get('host') or '?'), 'info')


def look(store, row, by=''):
    """The join as far as acme drives it: a passive agent reached (its request, or its
    certificate handed to it); an active one comes by itself. -> info."""
    st = state(store, row['id'])
    if mode_of(row) == 'passive':
        c = st.get('code') if isinstance(st.get('code'), dict) else None
        pend = st.get('pending') if isinstance(st.get('pending'), dict) else None
        try:
            if pend and pend.get('cert'):
                finish_passive(store, row, st)
            elif c and not c.get('used') and float(c.get('until') or 0) > time.time():
                secret = E.unseal_secret(c.get('secret'), M_T(row['id']) + ':code')
                nonce = secrets.token_hex(16)
                ans = join_answer(store, secret, c, nonce)
                body = dict(ans, i=c['id'], nonce=nonce)
                got, peer = _passive_post(store, row, '/v1/join', body, joining=True)
                if not got.get('ok'):
                    raise PluginError(_txt(got.get('said')) or 'the agent refused', retry=False)
                join_take(store, row, st, c, secret, got, tls_key_fp=peer)
            elif st.get('cert_fp'):
                hello(store, row)
        except (PluginError, OSError, ValueError) as e:
            st = state(store, row['id'])
            st['last_error'] = _txt(e, 400)
            state_put(store, row['id'], st)
            out = info(store, row)
            out['said'] = _txt(e, 400)
            return out
    return info(store, row)


# ---- the wire of an active agent (nginx -> agent.php -> here) -----------------------------------
def wire(store, op, body, cert_pem, verify, ip=''):
    """One request of an active agent: (status, answer). join and join/status come without a
    client certificate (the code proves them); poll only with one of the authority."""
    if not isinstance(body, dict):
        return 400, {'ok': False, 'said': 'not an object'}
    if not active_on():
        return 404, {'ok': False, 'said': 'the agents\' port is off'}
    if op == 'join':
        try:
            row, st, c, secret = _code_of(store, body.get('i'))
        except LookupError:
            return 403, {'ok': False, 'said': 'no such join code (or it ran out) - make a new one'}
        if mode_of(row) != 'active':
            return 403, {'ok': False, 'said': 'the target is passive: acme reaches it'}
        try:
            join_take(store, row, st, c, secret, body)
        except PluginError as e:
            return 403, {'ok': False, 'said': str(e)}
        return 200, join_answer(store, secret, c, str(body.get('nonce') or ''))
    if op == 'status':
        try:
            row, st, c, secret = _code_of(store, body.get('i'))
        except LookupError:
            return 403, {'ok': False, 'state': 'refused', 'said': 'no such join (make a new code)'}
        nonce = str(body.get('nonce') or '')
        if not re.fullmatch(r'[0-9a-f]{32}', nonce) or not hmac.compare_digest(
                proof(secret, 'status', c['id'], nonce), str(body.get('proof') or '')):
            return 403, {'ok': False, 'state': 'refused', 'said': 'not the agent of this code'}
        pend = st.get('pending') or {}
        if not pend:
            return 200, {'ok': True, 'state': 'waiting'}
        if not pend.get('cert'):
            return 200, {'ok': True, 'state': 'confirm', 'said': 'confirm the fingerprint in acme'}
        out = {'ok': True, 'state': 'done', 'cert_pem': pend['cert'], 'endpoints':
               endpoints(store), 'proof': proof(secret, 'cert', c['id'], hashlib.sha256(
                   pend['cert'].encode()).hexdigest(), nonce)}
        _joined(store, row)
        return 200, out
    if op == 'poll':
        return poll(store, body, cert_pem, verify, ip)
    return 404, {'ok': False, 'said': 'not here'}


def who_is(store, cert_pem, verify):
    """(row, state) of the agent a client certificate is - checked against what is pinned on
    every request: a target switched off or deleted, a certificate replaced, refused at once."""
    if str(verify or '') != 'SUCCESS' or not cert_pem:
        raise PluginError('a certificate of acme\'s agent authority is needed', retry=False)
    pem = str(cert_pem)
    if len(pem) > 16384:
        raise PluginError('not a certificate', retry=False)
    try:
        fp = fp_of_pem(pem)
    except (ValueError, ssl.SSLError):
        raise PluginError('not a certificate', retry=False)
    cn = _openssl(['x509', '-noout', '-subject', '-nameopt', 'RFC2253'], pem)
    m = re.search(r'CN=acme-agent:(ag-[0-9a-f]{12,32})', cn)
    if not m:
        raise PluginError('not an agent\'s certificate', retry=False)
    aid = m.group(1)
    tid = store.get_meta(M_ID(aid))
    row = store.db.row('SELECT * FROM cert_targets WHERE id = ?', (int(tid),)) \
        if tid and str(tid).isdigit() else None
    if not row or row.get('kind') != 'agent':
        raise PluginError('this agent is not one of acme\'s targets (deleted, or joined again)',
                          retry=False)
    st = state(store, row['id'])
    if st.get('agent_id') != aid or fp not in (st.get('cert_fp'), st.get('cert_prev_fp')) or \
            not fp:
        raise PluginError('this certificate is no longer the agent\'s (joined again, or '
                          'forgotten)', retry=False)
    if not (row.get('enabled') is None or int(row.get('enabled') or 0)):
        raise PluginError('the target is switched off in acme', retry=False)
    if mode_of(row) != 'active':
        raise PluginError('the target is passive in acme: it is not polled', retry=False)
    return row, st, fp


def poll(store, body, cert_pem, verify, ip=''):
    try:
        row, st, fp = who_is(store, cert_pem, verify)
    except PluginError as e:
        return 403, {'ok': False, 'said': str(e)}
    if body.get('agent') not in (None, '', st.get('agent_id')):
        return 403, {'ok': False, 'said': 'not this agent\'s id'}
    tid = row['id']
    # the results of the jobs it took
    for r in (body.get('results') if isinstance(body.get('results'), list) else [])[:20]:
        if not isinstance(r, dict):
            continue
        jid = str(r.get('job') or '')
        if not re.fullmatch(r'[0-9a-f]{24}', jid):
            continue
        q = store.get_meta('agentq:%d:%s' % (tid, jid))
        if not q:
            continue                                    # not a job of this agent's
        store.set_meta('agentr:%s' % jid, json.dumps(dict(clean_result(r.get('result')),
                                                          _at=time.time())))
        store.db.run('DELETE FROM meta WHERE k = ?', ('agentq:%d:%s' % (tid, jid),))
    now = time.time()
    facts = body.get('facts') if isinstance(body.get('facts'), dict) else {}
    changed = False
    if now - float(st.get('last_seen') or 0) > 15 or st.get('refused') or st.get('pending'):
        st['last_seen'] = now
        st['last_ip'] = _txt(ip, 45)
        changed = True
    if facts.get('version') and _txt(facts['version'], 40) != st.get('version'):
        st['version'] = _txt(facts['version'], 40)
        changed = True
    if facts.get('code') and _txt(facts['code'], 64) != st.get('code_hash'):
        st['code_hash'] = _txt(facts['code'], 64)
        changed = True
    if body.get('renew') and not st.get('renew_wanted'):
        st['renew_wanted'] = True
        changed = True
    if st.get('quiet'):
        st['quiet'] = False
        store.add_event('certificates', 'the agent of target %s is heard from again'
                        % row['name'])
    if st.get('pending') and st['pending'].get('cert') and fp == st.get('cert_fp'):
        st.pop('pending', None)
        st.pop('code', None)
    if changed:
        state_put(store, tid, st)
    jobs = _take(store, tid)
    held = False
    if not jobs and not body.get('results'):
        with LOCK:
            if HOLDING['n'] < HOLD_MOST:
                HOLDING['n'] += 1
                held = True
        if held:
            try:
                end = time.time() + HOLD_S
                while time.time() < end and not jobs:
                    time.sleep(0.4)
                    jobs = _take(store, tid)
            finally:
                with LOCK:
                    HOLDING['n'] -= 1
    return 200, {'ok': True, 'jobs': jobs, 'wait': 0 if jobs or held else 8}


def _take(store, tid):
    out = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", ('agentq:%d:%%' % tid,)):
        q = _jload(r['v'], {})
        if not isinstance(q, dict) or q.get('state') != 'queued':
            continue
        q['state'] = 'sent'
        q['sent'] = time.time()
        q['node'] = E.node_name()
        store.set_meta(r['k'], json.dumps(q))
        out.append(q['env'])
    return out[:20]


RESULT_KEYS = ('ok', 'said', 'steps', 'files', 'needs', 'refused', 'unchanged', 'policy',
               'policy_hash', 'version', 'code', 'host', 'os', 'enc_pub', 'csr', 'cert_fp',
               'cert_end', 'rolled_back', 'verified', 'chain', 'tls', 'cipher', 'kept',
               'key_fp', 'ms')


def clean_result(r):
    """An agent's answer, as acme takes it: known keys, of their shapes, cut to size."""
    if not isinstance(r, dict):
        return {'ok': False, 'said': 'the agent answered something that is not an object'}
    out = {'ok': bool(r.get('ok'))}
    for k in ('said', 'version', 'code', 'host', 'os', 'policy_hash', 'tls', 'cipher'):
        if r.get(k) is not None:
            out[k] = _txt(r[k], 800 if k == 'said' else 120)
    # what a probe saw (a chain of DER certificates, base64) and a key made there (its
    # fingerprint, whether the one in use was kept)
    if isinstance(r.get('chain'), list):
        chain = []
        for c in r['chain'][:10]:
            try:
                der = base64.b64decode(str(c), validate=True) if isinstance(c, str) and \
                    len(c) < 40000 else b''
            except (ValueError, TypeError):
                der = b''
            if der[:1] == b'\x30':
                chain.append(der)
        out['chain'] = chain
    if isinstance(r.get('key_fp'), str) and HEX64.match(r['key_fp']):
        out['key_fp'] = r['key_fp']
    if r.get('kept'):
        out['kept'] = True
    try:
        if r.get('ms') is not None:
            out['ms'] = max(0, int(r['ms']))
    except (TypeError, ValueError):
        pass
    for k in ('refused', 'unchanged', 'rolled_back'):
        if r.get(k):
            out[k] = True
    if isinstance(r.get('steps'), list):
        out['steps'] = []
        for s in r['steps'][:200]:
            if isinstance(s, (list, tuple)) and len(s) == 2:
                lv = s[0] if s[0] in ('info', 'ok', 'warn', 'bad') else 'info'
                out['steps'].append([lv, _txt(s[1], 600)])
    if isinstance(r.get('files'), list):
        out['files'] = [{'path': _txt(f.get('path'), 1024),
                         'sha256': str(f.get('sha256')) if HEX64.match(str(f.get('sha256') or ''))
                         else None, 'said': _txt(f.get('said'), 200)}
                        for f in r['files'][:200] if isinstance(f, dict)]
    if isinstance(r.get('needs'), list):
        out['needs'] = [{'kind': _txt(n.get('kind'), 20), 'what': _txt(n.get('what'), 300),
                         'allow': _txt(n.get('allow'), 600)}
                        for n in r['needs'][:50] if isinstance(n, dict)]
    if isinstance(r.get('policy'), dict):
        out['policy'] = clean_policy(r['policy'])
    if isinstance(r.get('csr'), str) and len(r['csr']) < 8192:
        out['csr'] = r['csr']
    if isinstance(r.get('enc_pub'), str) and len(r['enc_pub']) < 64:
        out['enc_pub'] = r['enc_pub']
    for k in ('cert_end',):
        try:
            if r.get(k) is not None:
                out[k] = float(r[k])
        except (TypeError, ValueError):
            pass
    if isinstance(r.get('cert_fp'), str) and HEX64.match(r['cert_fp']):
        out['cert_fp'] = r['cert_fp']
    return out


def clean_policy(p):
    """The policy as the agent reports it - its shape checked item by item."""
    def s(v, n=300):
        return _txt(v, n)
    out = {'hash': s(p.get('hash'), 64), 'files': [], 'units': {}, 'tests': [], 'scripts': [],
           'script_hashes': [], 'from': [], 'connect': [], 'probe': [], 'problems': [],
           'self_update': bool(p.get('self_update')), 'probe_local': bool(p.get('probe_local')),
           'limits': {'files': 20, 'size': 1048576}}
    for f in (p.get('files') or [])[:200]:
        if isinstance(f, dict) and isinstance(f.get('dir'), str) and f['dir'].startswith('/'):
            try:
                out['files'].append({'dir': s(f['dir'], 1024), 'owner': s(f.get('owner'), 32),
                                     'group': s(f.get('group'), 32),
                                     'mode': int(f.get('mode') or 0) & 0o777})
            except (TypeError, ValueError):
                continue
    units = p.get('units') if isinstance(p.get('units'), dict) else {}
    for u, vs in list(units.items())[:200]:
        if isinstance(vs, list):
            out['units'][s(u, 128)] = [s(v, 30) for v in vs[:8]]
    for t in (p.get('tests') or [])[:200]:
        if isinstance(t, list) and t:
            out['tests'].append([s(a, 1024) for a in t[:64]])
    for x in (p.get('scripts') or [])[:200]:
        if isinstance(x, dict) and HEX64.match(str(x.get('sha256') or '')):
            out['scripts'].append({'path': s(x.get('path'), 1024), 'sha256': x['sha256']})
    out['script_hashes'] = [h for h in (p.get('script_hashes') or [])[:500]
                            if isinstance(h, str) and HEX64.match(h)]
    out['from'] = [s(x, 60) for x in (p.get('from') or [])[:100]]
    out['connect'] = [s(x, 300) for x in (p.get('connect') or [])[:100]]
    out['probe'] = [s(x, 300) for x in (p.get('probe') or [])[:100]]
    out['problems'] = [s(x, 300) for x in (p.get('problems') or [])[:20]]
    lim = p.get('limits') if isinstance(p.get('limits'), dict) else {}
    for k in ('files', 'size'):
        try:
            out['limits'][k] = max(1, int(lim.get(k) or out['limits'][k]))
        except (TypeError, ValueError):
            pass
    return out


# ---- calling an agent ---------------------------------------------------------------------------
def _passive_ctx(store, joining=False):
    c = ctl(store)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    if joining:
        ctx.verify_mode = ssl.CERT_NONE          # the code's secret proves the agent
    else:
        ctx.load_verify_locations(cadata=ca(store)['cert_pem'])
        ctx.verify_mode = ssl.CERT_REQUIRED
    with tempfile.TemporaryDirectory() as t:
        cf, kf = os.path.join(t, 'c.pem'), os.path.join(t, 'k.pem')
        with open(cf, 'w') as f:
            f.write(c['cert_pem'])
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(c['key_pem'])
        ctx.load_cert_chain(cf, kf)
    return ctx


def _hostport(row):
    cfg = target_conf(row)
    host = str(cfg.get('host') or '').strip().strip('[]')
    if not host:
        raise PluginError('the target has no address: a passive agent is reached at it',
                          retry=False)
    try:
        port = int(cfg.get('port') or PASSIVE_PORT)
    except (TypeError, ValueError):
        port = PASSIVE_PORT
    return host, port


def _passive_post(store, row, path, body, joining=False, timeout=None):
    """(answer, the key fingerprint of the certificate the agent answered with) - its
    certificate checked: the one pinned (or, joining, its key against the request)."""
    host, port = _hostport(row)
    if timeout is None:
        try:
            timeout = float(target_conf(row).get('timeout') or 30)
        except (TypeError, ValueError):
            timeout = 30
    st = state(store, row['id'])
    via = str(target_conf(row).get('via') or '').strip()
    if via:
        conn = _ViaConnection(store, row, via, host, port, _passive_ctx(store, bool(joining)),
                              timeout)
    else:
        conn = http.client.HTTPSConnection(host, port, context=_passive_ctx(store, bool(joining)),
                                           timeout=timeout)
    try:
        raw = json.dumps(body).encode()
        conn.connect()
        der = conn.sock.getpeercert(True) or b''
        fp = hashlib.sha256(der).hexdigest()
        peer = None
        if joining:
            peer = spki_fp(ssl.DER_cert_to_PEM_cert(der))
            if isinstance(joining, str) and peer != joining:
                raise PluginError('the agent answers with another key than the one confirmed',
                                  retry=False)
        elif fp not in (st.get('cert_fp'), st.get('cert_prev_fp')) or not fp:
            raise PluginError('the agent at %s:%d answers with a certificate that is not the '
                              'one acme gave it - refused' % (host, port), retry=False)
        conn.request('POST', path, body=raw, headers={'Content-Type': 'application/json'})
        r = conn.getresponse()
        data = r.read(BODY_MOST + 1)
        if len(data) > BODY_MOST:
            raise PluginError('the agent\'s answer is too big', retry=False)
        try:
            got = json.loads(data.decode('utf-8') or '{}')
        except (ValueError, UnicodeDecodeError):
            raise PluginError('the agent answered HTTP %d, not JSON' % r.status)
        if not isinstance(got, dict):
            raise PluginError('the agent answered something that is not an object')
        if r.status != 200 and got.get('ok') is not False:
            got = {'ok': False, 'said': 'HTTP %d' % r.status}
        return got, peer
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        raise PluginError('the agent at %s:%d does not answer: %s' % (host, port, e))
    finally:
        conn.close()


# ---- a passive agent reached through an SSH connector (phase 3) ---------------------------------
def ssh_hop(store, row, via):
    """An SSH session to the connector `via` (Targets → Connector over SSH, or one of the
    tests') that a passive agent is reached through (ssh -W)."""
    from acmelib.certs import runtime, store as S
    from acmelib.plugins.targets._common import ssh_conn
    fam, crow = 'target', store.db.row("SELECT * FROM cert_targets WHERE name = ? AND kind = "
                                       "'ssh_connector'", (via,))
    if not crow:
        fam, crow = 'check', store.db.row("SELECT * FROM cert_tests WHERE name = ? AND kind = "
                                          "'ssh_relay'", (via,))
    if not crow:
        raise PluginError('there is no connector over SSH called %s - the agent of %s is reached '
                          'through it' % (via, row['name']), retry=False)
    if crow.get('enabled') == 0:
        raise PluginError('the connector %s is switched off' % via, retry=False)
    ctx = runtime.RunContext(store, None, scope='target:%s' % via, on_hostkey=False)
    conn = ssh_conn(S.plugin_instance(store, fam, crow, ctx))
    conn.update(via='', no_keep=True)
    try:
        return runtime.SshSession(ctx, conn)
    except PluginError as e:
        raise PluginError('signing in to the connector %s: %s' % (via, e))


class _ViaConnection(http.client.HTTPSConnection):
    """The HTTPS connection to a passive agent, opened from an SSH connector's server."""

    def __init__(self, store, row, via, host, port, context, timeout):
        http.client.HTTPSConnection.__init__(self, host, port, context=context, timeout=timeout)
        self._hop = (store, row, via)
        self._session = None

    def connect(self):
        store, row, via = self._hop
        self._session = ssh_hop(store, row, via)
        raw = self._session.tunnel(self.host, self.port, self.timeout or 30)
        self.sock = self._context.wrap_socket(raw, server_hostname=None)

    def close(self):
        http.client.HTTPSConnection.close(self)
        if self._session is not None:
            try:
                self._session.close()
            except Exception:                           # noqa: BLE001
                pass
            self._session = None


def call(store, row, op, args=None, timeout=900, step=None):
    """One signed job run by the agent of a target -> its answer (clean_result). PluginError
    when it cannot be asked at all; a refusal of the agent's is an answer (ok False)."""
    st = state(store, row['id'])
    if not st.get('cert_fp') or not st.get('agent_id'):
        raise PluginError('the agent of %s has not joined yet - make a join code on the target\'s '
                          'card' % row['name'], retry=False)
    if not (row.get('enabled') is None or int(row.get('enabled') or 0)):
        raise PluginError('the target is switched off', retry=False)
    jid, env = sign_job(store, st['agent_id'], op, args or {})
    mode = mode_of(row)
    t0 = time.time()
    try:
        if mode == 'passive':
            got, _peer = _passive_post(store, row, '/v1/job', env, timeout=timeout)
            got = clean_result(got)
        else:
            if not active_on():
                raise PluginError('the agents\' port is off (Settings → Target agents): an active '
                                  'agent cannot reach acme', retry=False)
            got = _queued(store, row, jid, env, timeout, step)
    except PluginError as e:
        st = state(store, row['id'])
        st['last_error'] = _txt(e, 400)
        state_put(store, row['id'], st)
        raise
    st = state(store, row['id'])
    st['last_seen'] = time.time()
    st['last_error'] = '' if got.get('ok') else _txt(got.get('said'), 400)
    if st.get('quiet'):
        st['quiet'] = False
        store.add_event('certificates', 'the agent of target %s is heard from again'
                        % row['name'])
    if got.get('policy'):
        _policy_seen(store, row, st, got['policy'])
    elif got.get('policy_hash') and got['policy_hash'] != (st.get('policy') or {}).get('hash'):
        st['policy_stale'] = True           # asked again below: the pages say it as it is now
    for k, n in (('version', 40), ('host', 120), ('os', 80)):
        if got.get(k):
            st[k] = _txt(got[k], n)
    if got.get('code'):
        st['code_hash'] = _txt(got['code'], 64)
    st['took_ms'] = int((time.time() - t0) * 1000)
    if op in ('deploy', 'keygen'):
        _blocked_seen(store, row, st, got, op)
    stale = st.pop('policy_stale', False)
    state_put(store, row['id'], st)
    if stale and op != 'hello':
        try:
            call(store, row, 'hello', {}, timeout=30)
        except PluginError:
            pass
    return got


def _queued(store, row, jid, env, timeout, step=None):
    k = 'agentq:%d:%s' % (row['id'], jid)
    store.set_meta(k, json.dumps({'env': env, 'state': 'queued', 'at': time.time(),
                                  'by': E.node_name()}))
    if step:
        step('the job is waiting for the agent to ask for it (active mode)')
    end = time.time() + timeout
    take_end = time.time() + min(TAKE_S, timeout)
    try:
        while time.time() < end:
            got = store.get_meta('agentr:%s' % jid)
            if got:
                store.db.run('DELETE FROM meta WHERE k = ?', ('agentr:%s' % jid,))
                return clean_result(_jload(got, {}))
            q = _jload(store.get_meta(k), None)
            if q is None:
                time.sleep(0.3)
                continue
            if q.get('state') == 'queued' and time.time() > take_end:
                st = state(store, row['id'])
                raise PluginError('the agent did not ask for the job in %d s (last heard from %s)'
                                  % (TAKE_S, _when(st.get('last_seen'))))
            time.sleep(0.3)
        raise PluginError('the agent did not answer the job in %d s' % timeout)
    finally:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))


def _blocked_seen(store, row, st, got, op):
    """A deployment (or a key made for one) refused by the agent's policy: said once (an
    event) and an alert until one goes through."""
    needs = got.get('needs') or []
    if not got.get('ok') and needs:
        what = '; '.join(n.get('what') or '' for n in needs[:4])
        was = st.get('blocked') if isinstance(st.get('blocked'), dict) else {}
        st['blocked'] = {'at': time.time(), 'op': op, 'what': _txt(what, 400),
                         'allow': [_txt(n.get('allow'), 300) for n in needs[:6]]}
        if was.get('what') != st['blocked']['what']:
            store.add_event('certificates', 'the policy of the agent of target %s blocks a '
                            'deployment: %s - allow it on the server (%s)' % (
                                row['name'], what, '; '.join(st['blocked']['allow'][:2])),
                            'warn')
    elif got.get('ok') and st.get('blocked'):
        st.pop('blocked', None)


def _policy_seen(store, row, st, pol):
    old = (st.get('policy') or {}).get('hash') if isinstance(st.get('policy'), dict) else None
    st['policy'] = pol
    st['policy_at'] = time.time()
    if old and old != pol.get('hash'):
        store.add_event('certificates', 'the policy of the agent of target %s changed on the '
                        'target (%s… → %s…)' % (row['name'], old[:12], str(pol.get('hash'))[:12]))


def hello(store, row, step=None):
    got = call(store, row, 'hello', {}, timeout=30, step=step)
    if not got.get('ok'):
        raise PluginError(got.get('said') or 'the agent refused', retry=False)
    return got


def renew_cert(store, row, by='the renewer', step=None):
    """The agent's certificate renewed over the channel: a CSR of its own key, signed, handed
    back; the one before let in for a while yet (jobs under way)."""
    tid = row['id']
    with LOCK:
        if tid in BUSY:
            raise PluginError('its certificate is being renewed already', retry=True)
        BUSY.add(tid)
    try:
        st = state(store, tid)
        got = call(store, row, 'csr', {}, timeout=120, step=step)
        if not got.get('ok') or not got.get('csr'):
            raise PluginError('the agent made no request: %s' % (got.get('said') or '?'))
        if spki_fp(got['csr']) != st.get('key_fp'):
            raise PluginError('the agent asks for a certificate of another key - join it again',
                              retry=False)
        pem = sign_csr(store, got['csr'], AGENT_CN + st['agent_id'], CERT_DAYS)
        old = st.get('cert_fp')
        st = state(store, tid)
        st['cert_prev_fp'] = old
        st['cert_fp'] = fp_of_pem(pem)
        st['cert_end'] = cert_end(pem)
        st['renew_wanted'] = False
        state_put(store, tid, st)
        try:
            ans = call(store, row, 'cert', {'cert_pem': pem}, timeout=120, step=step)
        except PluginError:
            ans = {'ok': False, 'said': 'it did not answer'}
        if not ans.get('ok'):
            st = state(store, tid)
            st['cert_fp'], st['cert_prev_fp'] = old, st['cert_fp']
            state_put(store, tid, st)
            raise PluginError('the agent did not take its new certificate: %s'
                              % (ans.get('said') or '?'))
        store.add_event('certificates', 'the certificate of the agent of target %s was renewed '
                        '(by %s) - valid until %s' % (row['name'], by, _when(cert_end(pem))))
        return cert_end(pem)
    finally:
        with LOCK:
            BUSY.discard(tid)


# ---- through the agent: a test of what is served, a connector (phase 3) ------------------------
def probe(store, row, host, port, sni='', starttls='', key_want='', timeout=15):
    """What host:port serves, seen from the agent's server (allow probe ... in its policy):
    {'chain': [DER...], 'tls', 'cipher', 'whole_chain'} as a test's served() gives it."""
    to = ('[%s]:%d' % (host, int(port))) if ':' in str(host) else '%s:%d' % (host, int(port))
    got = call(store, row, 'probe', {'to': to, 'sni': sni or '', 'starttls': starttls or '',
                                     'key_want': key_want or '', 'timeout': int(timeout or 15)},
               timeout=max(30, int(timeout or 15) + 15))
    if not got.get('ok'):
        needs = got.get('needs') or []
        raise PluginError('%s%s' % (got.get('said') or 'the agent refused the test',
                                    (' - on the server: ' + needs[0]['allow']) if needs else ''),
                          detail='\n'.join(n['allow'] for n in needs) or None,
                          retry=not needs and not got.get('refused'))
    if not got.get('chain'):
        raise PluginError('the agent saw no certificate at %s' % to)
    return {'chain': list(got['chain']), 'tls': got.get('tls') or '',
            'cipher': got.get('cipher') or '', 'whole_chain': True, 'alpn': ''}


def tunnel(store, row, host, port, timeout=20):
    """A socket to host:port opened by the agent's server (allow connect ... in its policy) -
    a passive agent only: acme opens a TLS connection to it (its certificate pinned), the signed
    job `connect` on it, and the bytes go both ways on that connection."""
    if mode_of(row) != 'passive':
        raise PluginError('the agent of %s is active (it connects to acme): a connector through '
                          'an agent needs a passive one' % row['name'], retry=False)
    st = state(store, row['id'])
    if not st.get('cert_fp') or not st.get('agent_id'):
        raise PluginError('the agent of %s has not joined yet' % row['name'], retry=False)
    if not (row.get('enabled') is None or int(row.get('enabled') or 0)):
        raise PluginError('the target %s is switched off' % row['name'], retry=False)
    to = ('[%s]:%d' % (host, int(port))) if ':' in str(host) else '%s:%d' % (host, int(port))
    _jid, env = sign_job(store, st['agent_id'], 'connect', {'to': to, 'timeout': int(timeout)})
    ahost, aport = _hostport(row)
    via = str(target_conf(row).get('via') or '').strip()
    hop = None
    try:
        if via:
            hop = ssh_hop(store, row, via)
            raw = hop.tunnel(ahost, aport, timeout)
        else:
            raw = socket.create_connection((ahost, aport), timeout=timeout)
        tls = _passive_ctx(store).wrap_socket(raw, server_hostname=None)
        fp = hashlib.sha256(tls.getpeercert(True) or b'').hexdigest()
        if fp not in (st.get('cert_fp'), st.get('cert_prev_fp')):
            tls.close()
            raise PluginError('the agent of %s answers with a certificate that is not the one '
                              'acme gave it - refused' % row['name'], retry=False)
        body = json.dumps(env).encode()
        tls.sendall(b'POST /v1/tunnel HTTP/1.1\r\nHost: acme-agent\r\nContent-Type: '
                    b'application/json\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
        head = b''
        while b'\r\n\r\n' not in head and len(head) < 16384:
            got = tls.recv(4096)
            if not got:
                break
            head += got
        line, _, rest = head.partition(b'\r\n')
        top, _, extra = rest.partition(b'\r\n\r\n')
        status = int((line.split(b' ') + [b'0', b'0'])[1] or 0) if line else 0
        if status != 200:
            n = 0
            for h in top.split(b'\r\n'):
                k, _, v = h.partition(b':')
                if k.strip().lower() == b'content-length':
                    n = int(v.strip() or 0)
            while len(extra) < min(n, 65536):
                more = tls.recv(4096)
                if not more:
                    break
                extra += more
            tls.close()
            try:
                said = clean_result(json.loads(extra.decode('utf-8', 'replace') or '{}'))
            except ValueError:
                said = {'said': 'HTTP %d' % status}
            needs = said.get('needs') or []
            raise PluginError('the agent of %s did not connect to %s: %s' % (
                row['name'], to, said.get('said') or 'HTTP %d' % status),
                detail='\n'.join(n['allow'] for n in needs) or None, retry=False)
    except (OSError, ssl.SSLError) as e:
        if hop is not None:
            hop.close()
        raise PluginError('the agent of %s cannot be reached: %s' % (row['name'], e))
    except BaseException:
        if hop is not None:
            hop.close()
        raise
    a, b = socket.socketpair()
    if extra:
        b.sendall(extra)

    def pump():
        try:
            agent_mod().relay(tls, b, 600)
        finally:
            for x in (tls, b):
                try:
                    x.close()
                except OSError:
                    pass
            if hop is not None:
                try:
                    hop.close()
                except Exception:                       # noqa: BLE001
                    pass
    threading.Thread(target=pump, daemon=True, name='agent-tunnel').start()
    a.settimeout(float(timeout))
    st = state(store, row['id'])
    st['last_seen'] = time.time()
    state_put(store, row['id'], st)
    return a


def connector_rows(store, passive_only=True):
    """The targets with an agent that can be a connector (passive, joined): [(name, row)]."""
    out = []
    for r in rows(store):
        if passive_only and mode_of(r) != 'passive':
            continue
        out.append(r)
    return out


# ---- updates of the agent (phase 4) ---------------------------------------------------------------
def _vt(v):
    try:
        return tuple(int(x) for x in str(v).strip().split('.'))
    except ValueError:
        return ()


def update_facts(st, pkg=None):
    """What the pages say of an agent's version: a newer one acme offers, whether the
    agent's policy lets acme update it."""
    if pkg is None:
        try:
            pkg = package(build=False)
        except Exception:                               # noqa: BLE001
            pkg = None
    import acmelib
    ver = (pkg or {}).get('version') or acmelib.__version__
    have = str(st.get('version') or '')
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    newer = bool(have) and bool(_vt(have)) and _vt(ver) > _vt(have)
    return {'offered': ver, 'newer': newer, 'signed': bool((pkg or {}).get('signed')),
            'allowed': bool(pol.get('self_update')), 'last': st.get('update_last') or None}


def update_agent(store, row, by):
    """acme's signed package of the agent sent to it (allow self-update): the agent checks
    the signature with the release key it was installed with, and that it is newer."""
    st = state(store, row['id'])
    pkg = package(build=False)
    if not pkg or not pkg.get('signed'):
        raise PluginError('this acme has no signed package of the agent (a release carries it; '
                          'one made from a source tree is never sent to an agent)', retry=False)
    facts = update_facts(st, pkg)
    if not facts['newer']:
        raise PluginError('the agent runs %s already - %s is not newer' % (
            st.get('version') or '?', pkg['version']), retry=False)
    with open(pkg['path'], 'rb') as f:
        data = f.read()
    got = call(store, row, 'update', {'package': _b64(data), 'version': pkg['version']},
               timeout=180)
    st = state(store, row['id'])
    st['update_last'] = {'at': time.time(), 'ok': bool(got.get('ok')), 'by': _txt(by, 120),
                         'said': _txt(got.get('said'), 300), 'to': pkg['version']}
    state_put(store, row['id'], st)
    if not got.get('ok'):
        store.add_event('certificates', 'the agent of target %s was not updated to %s: %s' % (
            row['name'], pkg['version'], got.get('said') or '?'), 'warn', who=by)
        needs = got.get('needs') or []
        raise PluginError(got.get('said') or 'the agent refused the update',
                          detail='\n'.join(n['allow'] for n in needs) or None, retry=False)
    store.add_event('certificates', 'the agent of target %s was updated to %s by %s' % (
        row['name'], pkg['version'], by), who=by)
    return got


def forget(store, row, by):
    """acme forgets the agent: its certificate no longer let in, its keys and policy gone."""
    st = state(store, row['id'])
    if st.get('agent_id'):
        store.db.run('DELETE FROM meta WHERE k = ?', (M_ID(st['agent_id']),))
    store.db.run('DELETE FROM meta WHERE k = ?', (M_T(row['id']),))
    store.db.run('DELETE FROM meta WHERE k LIKE ?', ('agentq:%d:%%' % row['id'],))
    store.add_event('certificates', 'the agent of target %s was forgotten by %s - it is no '
                    'longer let in (acme-agent forget on the target takes its side away)'
                    % (row['name'], by), 'warn', who=by)


def target_gone(store, row):
    """The target deleted: its agent no longer let in."""
    try:
        st = state(store, row['id'])
        if st.get('agent_id'):
            store.db.run('DELETE FROM meta WHERE k = ?', (M_ID(st['agent_id']),))
        store.db.run('DELETE FROM meta WHERE k = ?', (M_T(row['id']),))
    except Exception:                                   # noqa: BLE001
        pass


# ---- now and then (the leader) -------------------------------------------------------------------
def rows(store):
    return store.db.rows("SELECT * FROM cert_targets WHERE kind = 'agent' ORDER BY name")


def tick(store):
    """Every few minutes, on the node that leads: passive agents asked how they are, the
    agents' certificates renewed, codes run out, jobs left behind taken away, an agent not
    heard from said once."""
    now = time.time()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agentq:%'"):
        q = _jload(r['v'], {})
        if not isinstance(q, dict) or now - float(q.get('at') or 0) > 3600:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agentr:%'"):
        got = _jload(r['v'], {})
        if not isinstance(got, dict) or now - float(got.get('_at') or 0) > 3600:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))     # its caller is gone
    for row in rows(store):
        if not (row.get('enabled') is None or int(row.get('enabled') or 0)):
            continue
        st = state(store, row['id'])
        if not st.get('cert_fp'):
            continue
        mode = mode_of(row)
        try:
            if mode == 'passive' and now - float(st.get('last_seen') or 0) > HELLO_EVERY_S:
                try:
                    hello(store, row)
                except PluginError:
                    pass
                st = state(store, row['id'])
            due = float(st.get('cert_end') or 0) - now < RENEW_DAYS * 86400 or \
                st.get('renew_wanted')
            if due and row['id'] not in BUSY and float(st.get('cert_end') or 0) > now and \
                    (mode == 'passive' or now - float(st.get('last_seen') or 0) < QUIET_S):
                threading.Thread(target=_renew_quietly, args=(store, row), daemon=True,
                                 name='agent-renew').start()
            quiet = now - float(st.get('last_seen') or 0) > QUIET_S
            if quiet and not st.get('quiet'):
                st = state(store, row['id'])
                st['quiet'] = True
                state_put(store, row['id'], st)
                store.add_event('certificates', 'the agent of target %s has not been heard from '
                                'since %s' % (row['name'], _when(st.get('last_seen'))), 'warn')
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('agent-tick-%s' % row['id'], 'the agent of %s: %s' % (row['name'], e),
                          'warn', every=3600)


def _renew_quietly(store, row):
    try:
        renew_cert(store, row)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('agent-renew-%s' % row['id'], 'renewing the certificate of the agent of '
                      '%s: %s' % (row['name'], e), 'warn', every=3600)


def alerts(store):
    out = []
    now = time.time()
    for row in rows(store):
        if not (row.get('enabled') is None or int(row.get('enabled') or 0)):
            continue
        st = state(store, row['id'])
        if not st.get('cert_fp'):
            continue
        seen = float(st.get('last_seen') or 0)
        if now - seen > QUIET_S:
            out.append({'key': 'agent-quiet:%s' % row['id'], 'level': 'warn',
                        'words': 'the agent of target %s has not been heard from since %s'
                                 % (row['name'], _when(seen) if seen else 'it joined')})
        blk = st.get('blocked') if isinstance(st.get('blocked'), dict) else None
        if blk:
            out.append({'key': 'agent-policy:%s' % row['id'], 'level': 'warn',
                        'words': 'the policy of the agent of target %s blocks a deployment (%s) '
                                 '- allow it on the server: %s' % (
                                     row['name'], blk.get('what') or '?',
                                     '; '.join((blk.get('allow') or [])[:2]))})
        end = float(st.get('cert_end') or 0)
        if end and end - now < 7 * 86400:
            out.append({'key': 'agent-cert:%s' % row['id'],
                        'level': 'bad' if end < now else 'warn',
                        'words': 'the certificate of the agent of target %s %s %s' % (
                            row['name'], 'ended' if end < now else 'ends', _when(end))})
    return out


# ---- the package an agent is installed from ---------------------------------------------------
PKG_RE = re.compile(r'acme-agent-(\d+\.\d+\.\d+)\.tar\.gz\Z')
_PKG = {}


def package(build=True):
    """The agent's package: the signed one a release put beside the program
    (deploy/agent/acme-agent-X.Y.Z.tar.gz), else one made here from the program (not signed -
    a source tree, not a release). {name, version, sha256, size, signed, path}."""
    import acmelib
    ver = acmelib.__version__
    try:
        names = sorted(n for n in os.listdir(AGENT_DIR) if PKG_RE.match(n))
    except OSError:
        names = []
    for n in reversed(names):
        if PKG_RE.match(n).group(1) == ver:
            p = os.path.join(AGENT_DIR, n)
            return _pkg_facts(p, n, ver, True)
    if not build:
        return None
    with LOCK:
        code = shipped_code()
        got = _PKG.get('built')
        if got and got['code'] == code and os.path.exists(got['path']):
            return dict(got)
        folder = os.path.join(str(E.STATE_DIR), 'agent-package')
        os.makedirs(folder, mode=0o750, exist_ok=True)
        name = 'acme-agent-%s.tar.gz' % ver
        path = os.path.join(folder, name)
        build_package(path, ver, key=None)
        got = _pkg_facts(path, name, ver, False)
        got['code'] = code
        _PKG['built'] = dict(got)
        return got


def _pkg_facts(path, name, ver, signed):
    with open(path, 'rb') as f:
        data = f.read()
    return {'name': name, 'version': ver, 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'signed': signed, 'path': path}


def build_package(dest, version, key=None, keys_dir=None, epoch=None):
    """The agent's package - made by the agent's own program (deploy/agent/acme_agent.py
    build_package), which tools/release.py uses too."""
    try:
        return agent_mod().build_package(dest, version, key=key, keys_dir=keys_dir, epoch=epoch)
    except agent_mod().Refused as e:
        raise PluginError(str(e), retry=False)
