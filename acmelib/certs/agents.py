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
    agents:enroll:<e>  a company enrollment code (1.0.120): its title, mode, until, how many
                       servers may join with it, who made it, its secret (sealed) - each
                       server that joins with it becomes a target of its own
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
import math
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
RENEW_ASK_S = 3600              # an agent's own ask for its certificate renewed: once an hour
BODY_MOST = 4 * 1024 * 1024
SEAL_ALG = 'X25519-HKDF-SHA256-A256GCM'
AGENT_ID_RE = re.compile(r'ag-[0-9a-f]{12,32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
LOCK = threading.RLock()
HOLDING = {'n': 0}
BUSY = set()                    # targets whose certificate is being renewed (this node)
ASKING = set()                  # active agents asked their policy (this node)

M_CA, M_CMD, M_CTL = 'agents:ca', 'agents:cmd', 'agents:ctl'
# the kinds of target with acme-agent (1.0.120): a Linux / Unix server, a Windows server - an
# agent everywhere (cards, join, monitoring, connectors, tests through it)
AGENT_KINDS = ('agent', 'agent_windows')
KINDS_SQL = "('agent', 'agent_windows')"


def is_agent_kind(k):
    return str(k or '') in AGENT_KINDS


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


def _load_agent_file(name, fn):
    spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT_DIR, fn))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def agent_mod_windows():
    """acme_agent.py as it reasons on Windows (1.0.120: acme_agent_win.install - its paths
    C:\\..., its protected places, services, PowerShell scripts): what a deployment to a Windows
    server needs of its policy, with the very code its agent runs. Only its pure checks are
    used here - nothing of Windows is ever called. The Linux one when it cannot be had."""
    if 'w' not in _AGENT:
        try:
            m = _load_agent_file('acme_agent_program_win', 'acme_agent.py')
            if not getattr(m, 'WINDOWS', False):
                w = _load_agent_file('acme_agent_win_program', 'acme_agent_win.py')
                inst = getattr(w, 'install_checks', None) or w.install
                inst(m.__dict__)
            _AGENT['w'] = m if getattr(m, 'WINDOWS', False) else None
        except Exception as e:                          # noqa: BLE001
            E.log('agents: the Windows agent\'s checks cannot be loaded: %s' % e, 'warn')
            _AGENT['w'] = None
    return _AGENT['w'] or agent_mod()


def wincert_mod():
    """deploy/agent/acme_agent_wincert.py: the agent's own words for the machine store, IIS and
    the Remote Desktop listener (the policy's allow store / iis / rdp)."""
    if 'wc' not in _AGENT:
        _AGENT['wc'] = _load_agent_file('acme_agent_wincert_program', 'acme_agent_wincert.py')
    return _AGENT['wc']


def platform_of(store, row):
    """'windows' or 'linux': the kind of the target, else what its agent said."""
    if (row or {}).get('kind') == 'agent_windows':
        return 'windows'
    try:
        st = state(store, row['id'])
    except Exception:                                   # noqa: BLE001
        st = {}
    return 'windows' if (st or {}).get('platform') == 'windows' else 'linux'


def agent_mod_for(platform):
    return agent_mod_windows() if platform == 'windows' else agent_mod()


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


def _txt(v, most=300, lines=False):
    """Words of the agent's, as words: no control characters, cut - and one line (1.0.116
    security: a host name or an answer with a line break in it went on as lines of their own
    into Events, the SIEM and the log - an event of the agent's own making). `lines`: the
    steps of a deployment, shown as they are, keep theirs."""
    t = str(v if v is not None else '')
    if not lines:
        t = re.sub(r'[\t\r\n\u2028\u2029\x85]+', ' ', t)
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]', '', t)[:most]


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
    if not row or not is_agent_kind(row.get('kind')):
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
            if not name or name.split('.')[0] in ('localhost', 'localhost6', 'ip6-localhost') \
                    or name.startswith('127.') or name == '::1':
                name = ''                               # never point an agent at itself
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
    # 1.0.120: a Windows server's agent (agent_windows), and the enrollment code it came with
    out['kind'] = row.get('kind') or 'agent'
    out['platform'] = st.get('platform') or ('windows' if out['kind'] == 'agent_windows'
                                             else 'linux')
    en = st.get('enroll') if isinstance(st.get('enroll'), dict) else None
    out['enroll'] = {'id': en.get('e'), 'title': en.get('title') or '',
                     'fqdn': en.get('fqdn') or '', 'at': en.get('at')} if en else None
    if out['pending'] is not None:
        out['pending'].update(os=pend.get('os') or '', ip=pend.get('ip') or '',
                              fqdn=pend.get('fqdn') or '',
                              enroll={'id': pend['enroll'], 'title': pend.get('enroll_title')
                                      or ''} if pend.get('enroll') else None)
    out['update'] = update_facts(st) if joined else None
    blk = st.get('blocked') if isinstance(st.get('blocked'), dict) else None
    out['blocked'] = {'at': blk.get('at'), 'what': blk.get('what') or '',
                      'allow': list(blk.get('allow') or [])} if blk else None
    out['via'] = str(target_conf(row).get('via') or '')
    # the certificates whose key its agent makes (phase 3)
    out['keys_of'] = [r['name'] for r in store.db.rows(
        'SELECT name FROM certs WHERE csr_from = ? ORDER BY name', (row['name'],))][:50]
    # the policy designed for it in acme (1.0.118, agent_policy.py) - documentation only
    try:
        from acmelib.certs import agent_policy
        out['design'] = agent_policy.design_summary(store, row, pol)
    except Exception:                                   # noqa: BLE001
        out['design'] = None
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


_SHIPPED = {}


def shipped_code():
    """The hash of the program acme ships - kept while its files are the same (1.0.119: the
    pages hashed it once for every agent of a list, and every few seconds)."""
    try:
        m = agent_mod()
        key = []
        for n in getattr(m, 'AGENT_FILES', ()):
            try:
                f = os.stat(os.path.join(AGENT_DIR, n))
                key.append((n, f.st_mtime_ns, f.st_size, f.st_ino))
            except OSError:
                key.append((n, None))
        key = tuple(key)
        if key and _SHIPPED.get('key') == key:
            return _SHIPPED['code']
        code = m.code_hash(AGENT_DIR)
        _SHIPPED.update(key=key, code=code)
        return code
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
            if not row or not is_agent_kind(row.get('kind')):
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
    if c.get('used') and not isinstance(st.get('pending'), dict):
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
    was = st.get('pending') if isinstance(st.get('pending'), dict) else {}
    if c.get('used'):
        # 1.0.119: the code is used once - only the agent that used it may ask again (its
        # answer lost, sent twice): the same key, the same key to seal to. Its CSR is made anew
        # each time (a signature of its own), so the key is compared, never the CSR's text
        if not was.get('fp') or not hmac.compare_digest(was['fp'], fp) or \
                not hmac.compare_digest(str(was.get('enc_pub') or ''), enc):
            raise PluginError('the join code was used already - make a new one', retry=False)
        if was.get('cert'):
            # once a person confirmed it: the pending request was made anew without its
            # certificate - the confirmation undone
            return fp
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


def _endpoints_proved(store, secret, c, nonce, out):
    """acme's addresses for an active agent, with acme's proof of them by the code's secret
    (1.0.116 security: the agent pins only proven ones - its join is TLS without a pinned
    certificate yet, so somebody between could have handed it addresses of theirs)."""
    eps = endpoints(store) if c.get('mode') == 'active' else []
    out['endpoints'] = eps
    if eps:
        out['endpoints_proof'] = proof(secret, 'endpoints', c['id'], json.dumps(
            eps, separators=(',', ':')), nonce)
    return out


def join_answer(store, secret, c, nonce):
    a = ca(store)
    ck = cmd_key(store)
    pub = _b64(ck['public'])
    return _endpoints_proved(store, secret, c, nonce, {
        'ok': True, 'agent_id': c['agent_id'], 'ca_pem': a['cert_pem'], 'cmd_pub': pub,
        'proof': proof(secret, 'joined', c['id'], hashlib.sha256(a['cert_pem'].encode())
                       .hexdigest(), pub, c['agent_id'], nonce)})


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
              joined_at=time.time(), refused='', last_error='', mode=mode_of(row),
              os=pend.get('os') or st.get('os') or '')
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
    err = None
    try:
        got, _peer = _passive_post(store, row, '/v1/join/finish', body, joining=pend['fp'])
    except PluginError as e:
        got, err = {}, e
    if not got.get('ok') and _has_its_cert(store, row):
        got = {'ok': True}
    if err is not None and not got.get('ok'):
        raise err
    if not got.get('ok'):
        raise PluginError('the agent did not take its certificate: %s' % _txt(got.get('said')),
                          retry=True)
    _joined(store, row)
    return True


def _has_its_cert(store, row):
    """1.0.119: the agent took its certificate, its answer lost (it serves it now, the join
    over on its side - asked again it says "no join under way"): it answers a job over its
    certificate, the one acme gave it - so it has it."""
    try:
        hello(store, row)
        return True
    except (PluginError, OSError, ValueError):
        return False


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
            if pend and pend.get('cert') and pend.get('enroll'):
                # 1.0.120: joined by an enrollment code - it takes its certificate by asking
                # acme (join/status), then listens: its first answer ends the join (call)
                if pend.get('handed'):
                    hello(store, row)
            elif pend and pend.get('cert'):
                finish_passive(store, row, st)
            elif c and not c.get('used') and float(c.get('until') or 0) > time.time():
                secret = E.unseal_secret(c.get('secret'), M_T(row['id']) + ':code')
                nonce = secrets.token_hex(16)
                ans = join_answer(store, secret, c, nonce)
                body = dict(ans, i=c['id'], nonce=nonce)
                got, peer = _passive_post(store, row, '/v1/join', body, joining=True)
                if not got.get('ok') and st.get('cert_fp') and peer and \
                        peer == st.get('key_fp'):
                    # the agent joined before answers (its key the one pinned): nothing joins
                    # with the code made yet - it is asked how it is (the code waits, its hour)
                    hello(store, row)
                else:
                    if not got.get('ok'):
                        raise PluginError(_txt(got.get('said')) or 'the agent refused',
                                          retry=False)
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
    elif st.get('cert_fp') and not st.get('pending') and active_on():
        # 1.0.118: "Ask it now" of an active agent asks it (a job its next poll takes) - it
        # showed the policy it said last, however old
        try:
            hello(store, row)
        except (PluginError, OSError, ValueError) as e:
            out = info(store, row)
            out['said'] = _txt(e, 400)
            return out
    return info(store, row)


# ---- the company enrollment code (1.0.120) ------------------------------------------------------
# One code for many servers: each server that joins with it (acme-agent join ACAE1..., the MSI's
# JOINCODE=, install.sh --join) becomes a target of its own, waiting for a person to confirm
# its fingerprint - one by one or many at once. The code's secret never joins anything itself:
# each target gets a join code of its own whose secret is derived from it (never sent).
M_E_PREFIX = 'agents:enroll:'
ENROLL_DAYS_MOST = 365
ENROLL_MOST = 10000
ENROLL_KEEP_S = 30 * 86400              # a code that ended is still listed this long
ENROLL_ID = re.compile(r'[0-9a-f]{12}\Z')


def M_E(eid):
    return M_E_PREFIX + str(eid)


def enroll_get(store, eid):
    if not ENROLL_ID.match(str(eid or '')):
        return None
    got = _jload(store.get_meta(M_E(eid)), None)
    return got if isinstance(got, dict) and got.get('id') == eid else None


def _enroll_put(store, ec):
    store.set_meta(M_E(ec['id']), json.dumps(ec, sort_keys=True))


def enroll_state(ec, now=None):
    """active | expired | used | revoked"""
    now = time.time() if now is None else now
    if ec.get('revoked'):
        return 'revoked'
    if float(ec.get('until') or 0) < now:
        return 'expired'
    if int(ec.get('uses') or 0) >= int(ec.get('most') or 1):
        return 'used'
    return 'active'


def enroll_view(store, ec, now=None):
    """What the pages show of an enrollment code - never its secret."""
    names = []
    for tid in list(ec.get('targets') or [])[:200]:
        try:
            r = store.db.row('SELECT name FROM cert_targets WHERE id = ?', (int(tid),))
        except (TypeError, ValueError):
            r = None
        if r:
            names.append(r['name'])
    rv = ec.get('revoked') if isinstance(ec.get('revoked'), dict) else None
    return {'id': ec['id'], 'title': ec.get('title') or '', 'mode': ec.get('mode') or 'passive',
            'port': ec.get('port'), 'until': ec.get('until'), 'most': int(ec.get('most') or 1),
            'uses': int(ec.get('uses') or 0), 'by': ec.get('by') or '', 'at': ec.get('at'),
            'auto': bool(ec.get('auto')), 'state': enroll_state(ec, now), 'targets': names,
            'revoked_by': (rv or {}).get('by') or '', 'revoked_at': (rv or {}).get('at')}


def enroll_list(store):
    now = time.time()
    out = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:enroll:%'"):
        ec = _jload(r['v'], None)
        if isinstance(ec, dict) and ENROLL_ID.match(str(ec.get('id') or '')):
            out.append(enroll_view(store, ec, now))
    out.sort(key=lambda x: (x['state'] != 'active', -float(x.get('at') or 0)))
    return out


def _int_in(v, lo, hi, what, default):
    try:
        n = int(default if v in (None, '') else v)
    except (TypeError, ValueError):
        raise PluginError('%s is a whole number' % what, retry=False)
    if not lo <= n <= hi:
        raise PluginError('%s is %d to %d' % (what, lo, hi), retry=False)
    return n


def enroll_new(store, by, title='', mode='passive', port=PASSIVE_PORT, days=7, most=10,
               auto=False):
    """A company enrollment code: {code (shown once), and what enroll_view says}."""
    if not active_on():
        raise PluginError('the agents\' port is off: an enrolling agent always asks acme there '
                          '- switch it on at Settings → Target agents (Agents may connect to '
                          'acme) first', retry=False)
    mode = str(mode or 'passive')
    if mode not in ('passive', 'active'):
        raise PluginError('the mode is passive or active', retry=False)
    port = _int_in(port, 1, 65535, 'the port', PASSIVE_PORT)
    days = _int_in(days, 1, ENROLL_DAYS_MOST, 'valid for (days)', 7)
    most = _int_in(most, 1, ENROLL_MOST, 'at most (servers)', 10)
    title = _txt(title, 80).strip() or 'Enrollment code'
    a = ca(store)
    ck = cmd_key(store)
    ctl(store)
    eid = secrets.token_hex(6)
    secret = secrets.token_urlsafe(24)
    now = time.time()
    until = now + days * 86400
    ec = {'id': eid, 'title': title, 'mode': mode, 'port': port, 'until': until, 'most': most,
          'uses': 0, 'targets': [], 'by': _txt(by, 120), 'at': now, 'auto': bool(auto),
          'secret': E.seal_secret(secret, M_E(eid))}
    _enroll_put(store, ec)
    data = {'v': 1, 'e': eid, 's': secret, 'ca': a['fp'], 'ck': ck['fp'], 'a': endpoints(store),
            'm': mode, 'p': port, 'u': int(until), 'n': title}
    code = 'ACAE1.' + base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':'))
                                               .encode()).decode().rstrip('=')
    store.add_event('certificates', 'the enrollment code "%s" was made by %s (%s, %d day%s, at '
                    'most %d server%s)%s' % (
                        title, by, mode, days, '' if days == 1 else 's', most,
                        '' if most == 1 else 's',
                        ' - each server that joins with it is CONFIRMED AUTOMATICALLY' if auto
                        else ' - each server that joins with it waits to be confirmed'),
                    'warn' if auto else 'info', who=by)
    return dict(enroll_view(store, ec, now), code=code, ca_fp=a['fp'],
                endpoints=data['a'])


def enroll_revoke(store, eid, by):
    ec = enroll_get(store, eid)
    if not ec:
        raise LookupError('there is no such enrollment code')
    if ec.get('revoked'):
        return enroll_view(store, ec)
    ec['revoked'] = {'by': _txt(by, 120), 'at': time.time()}
    _enroll_put(store, ec)
    store.add_event('certificates', 'the enrollment code "%s" was revoked by %s (%d server%s '
                    'joined with it) - no other server joins with it' % (
                        ec.get('title') or ec['id'], by, int(ec.get('uses') or 0),
                        '' if int(ec.get('uses') or 0) == 1 else 's'), who=by)
    return enroll_view(store, ec)


def _enrolled_row(store, fqdn, fp):
    """The target a server enrolled as before (the same name, the same key) - or None."""
    for row in rows(store):
        en = state(store, row['id']).get('enroll')
        if isinstance(en, dict) and en.get('fqdn') == fqdn and en.get('key_fp') == fp:
            return row
    return None


def _enroll_name(store, host, fqdn, ip):
    from acmelib.certs import store as S
    base = str(host or '').strip().lower() or str(fqdn or '').strip().lower()
    base = base.split('.')[0] if base and not re.match(r'[0-9.]+\Z', base) else base
    base = re.sub(r'[^a-z0-9._@+-]+', '-', base).strip('-.')[:100]
    if not base or not S.NAME_RE.match(base):
        base = 'server-' + re.sub(r'[^0-9a-f]', '-', str(ip or 'x'))[:40].strip('-')
        if not S.NAME_RE.match(base):
            base = 'server'
    name, n = base, 1
    while store.db.row('SELECT id FROM cert_targets WHERE name = ?', (name,)):
        n += 1
        name = '%s-%d' % (base, n)
    return name


def _enroll_target(store, ec, kind, host, fqdn, ip):
    """The target a new server enrolls as: the kind of its platform, its host name (made
    unique), reached at its name (else the address it came from), the code's mode and port."""
    from acmelib.certs import api as A, store as S
    addr = fqdn if fqdn and '.' in fqdn and not fqdn.startswith('localhost') and \
        S.DNS_RE.match(fqdn) else str(ip or '')
    cfg = {'mode': ec.get('mode') or 'passive', 'host': addr}
    if cfg['mode'] == 'passive':
        cfg['port'] = int(ec.get('port') or PASSIVE_PORT)
    by = 'the enrollment code "%s"' % (ec.get('title') or ec['id'])
    last = None
    for _ in range(5):
        name = _enroll_name(store, host, fqdn, ip)
        try:
            rid = A.family_save(store, 'target', {
                'name': name, 'kind': kind, 'config': cfg, 'enabled': 1,
                'note': 'enrolled by %s' % by}, by)
            return S.plugin_row(store, 'target', rid)
        except ValueError as e:                         # taken meanwhile (another node)
            last = e
    raise PluginError('the target could not be made: %s' % last, retry=False)


def _target_code(store, row, st, eid, secret_e, until, by):
    """A join code of the target's own, its secret derived from the enrollment code's."""
    cid = secrets.token_hex(6)
    c = {'id': cid, 'secret': E.seal_secret(proof(secret_e, 'target', eid, cid),
                                            M_T(row['id']) + ':code'),
         'until': until, 'agent_id': 'ag-' + secrets.token_hex(8), 'mode': mode_of(row),
         'tries': 0, 'by': by, 'at': time.time(), 'enroll': eid}
    st['code'] = c
    st.pop('pending', None)
    st['mode'] = mode_of(row)
    state_put(store, row['id'], st)
    return c


def _enroll_refused(store, ec, ip, words):
    """Said once a minute at most for a code (an event of the agent's own making otherwise)."""
    now = time.time()
    if now - float(ec.get('refused_at') or 0) < 60:
        return
    ec['refused_at'] = now
    _enroll_put(store, ec)
    store.add_event('certificates', 'an agent from %s was refused by the enrollment code "%s": '
                    '%s' % (_txt(ip, 45) or '?', ec.get('title') or ec['id'], words), 'warn')


def enroll_take(store, body, ip=''):
    """An agent joining with an enrollment code (POST /agent/v1/enroll) -> (status, answer):
    the target it is (made the first time), the join taken as `join` takes it, and acme's
    answer as `join` answers plus {i, target} - the agent goes on as an active join of `i`."""
    eid = str(body.get('e') or '')
    ec = enroll_get(store, eid)
    if not ec:
        return 403, {'ok': False, 'said': 'no such enrollment code - make one in acme '
                                          '(Settings → Target agents → Enrollment codes)'}
    secret = E.unseal_secret(ec.get('secret'), M_E(eid))
    if not secret:
        return 403, {'ok': False, 'said': 'the enrollment code does not open on this node'}
    csr, enc = str(body.get('csr') or ''), str(body.get('enc_pub') or '')
    nonce, fqdn_said = str(body.get('nonce') or ''), str(body.get('fqdn') or '')
    want = proof(secret, 'enroll', eid, hashlib.sha256(csr.encode()).hexdigest(), enc, nonce,
                 fqdn_said)
    if not re.fullmatch(r'[0-9a-f]{32}', nonce) or \
            not hmac.compare_digest(want, str(body.get('proof') or '')):
        _enroll_refused(store, ec, ip, 'its request does not prove the code')
        return 403, {'ok': False, 'said': 'the request does not prove the enrollment code'}
    now = time.time()
    st_e = enroll_state(ec, now)
    if st_e == 'revoked':
        return 403, {'ok': False, 'said': 'the enrollment code was revoked in acme - ask for a '
                                          'new one'}
    if st_e == 'expired':
        return 403, {'ok': False, 'said': 'the enrollment code ran out - ask for a new one'}
    try:
        fp = spki_fp(csr)
    except PluginError as e:
        return 400, {'ok': False, 'said': str(e)}
    fqdn = _txt(fqdn_said, 253).strip().lower().rstrip('.')
    host = _txt(body.get('host'), 120).strip()
    windows = str(body.get('platform') or '') == 'windows'
    kind = 'agent_windows' if windows else 'agent'
    by = 'the enrollment code "%s"' % (ec.get('title') or eid)
    with LOCK:
        row = _enrolled_row(store, fqdn, fp)
        made = False
        if row is None:
            ec = enroll_get(store, eid) or ec
            if enroll_state(ec, now) == 'used':
                _enroll_refused(store, ec, ip, 'it was used by as many servers as it allows')
                return 403, {'ok': False, 'said': 'the enrollment code was used by as many '
                                                  'servers as it allows (%d) - ask for a new one'
                                                  % int(ec.get('most') or 1)}
            try:
                row = _enroll_target(store, ec, kind, host, fqdn, ip)
            except (PluginError, ValueError, LookupError) as e:
                return 403, {'ok': False, 'said': 'acme could not make the target: %s' % e}
            made = True
            ec['uses'] = int(ec.get('uses') or 0) + 1
            ec['targets'] = (list(ec.get('targets') or []) + [row['id']])[-ENROLL_MOST:]
            _enroll_put(store, ec)
        st = state(store, row['id'])
        c = st.get('code') if isinstance(st.get('code'), dict) else None
        if not c or c.get('enroll') != eid or float(c.get('until') or 0) < now:
            c = _target_code(store, row, st, eid, secret, max(now + CODE_S,
                                                              float(ec.get('until') or 0)), by)
            st = state(store, row['id'])
        secret_t = proof(secret, 'target', eid, c['id'])
        req = {'csr': csr, 'enc_pub': enc, 'nonce': nonce, 'version': body.get('version'),
               'code': body.get('code'), 'host': host,
               'proof': proof(secret_t, 'join', c['id'], hashlib.sha256(csr.encode())
                              .hexdigest(), enc, nonce)}
        try:
            join_take(store, row, st, c, secret_t, req)
        except PluginError as e:
            return 403, {'ok': False, 'said': str(e)}
        st = state(store, row['id'])
        pend = st.get('pending') or {}
        osn = _txt(body.get('os'), 80)
        pend.update(enroll=eid, enroll_title=ec.get('title') or '', fqdn=fqdn, ip=_txt(ip, 45),
                    os=osn, platform='windows' if windows else 'linux')
        st['pending'] = pend
        st['enroll'] = {'e': eid, 'title': ec.get('title') or '', 'fqdn': fqdn, 'key_fp': fp,
                        'platform': pend['platform'], 'at': st['enroll'].get('at', now)
                        if isinstance(st.get('enroll'), dict) else now}
        st['platform'] = pend['platform']
        if osn:
            st['os'] = osn
        state_put(store, row['id'], st)
    if made:
        store.add_event('certificates', 'a server enrolled with %s: target %s (%s, %s, %s, key '
                        '%s…)%s' % (by, row['name'], fqdn or host or '?', _txt(ip, 45) or '?',
                                    'Windows' if windows else 'Linux', fp[:16],
                                    ' - confirmed automatically' if ec.get('auto') else
                                    ' - it waits for its fingerprint to be confirmed'), 'info')
    if ec.get('auto') and not pend.get('cert'):
        try:
            confirm(store, row, fp, '%s (confirmed automatically)' % by)
        except PluginError as e:
            E.log('agent enrollment: confirming %s automatically: %s' % (row['name'], e), 'warn')
    out = join_answer(store, secret_t, c, nonce)
    out.update(i=c['id'], target=row['name'])
    return 200, out


def waiting(store):
    """Every agent asking to join, not confirmed yet: the target, the server, its fingerprint,
    the enrollment code it came with (or the target's own join code)."""
    out = []
    for row in rows(store):
        st = state(store, row['id'])
        pend = st.get('pending') if isinstance(st.get('pending'), dict) else None
        if not pend or pend.get('cert') or not pend.get('fp'):
            continue
        cfg = target_conf(row)
        out.append({'id': row['id'], 'name': row['name'], 'kind': row.get('kind'),
                    'platform': pend.get('platform') or st.get('platform') or (
                        'windows' if row.get('kind') == 'agent_windows' else 'linux'),
                    'mode': mode_of(row), 'host': pend.get('host') or '',
                    'fqdn': pend.get('fqdn') or '', 'ip': pend.get('ip') or '',
                    'address': str(cfg.get('host') or ''), 'os': pend.get('os') or '',
                    'version': pend.get('version') or '', 'fp': pend['fp'],
                    'fp_words': fp_words(pend['fp']), 'at': pend.get('at'),
                    'enroll': {'id': pend['enroll'], 'title': pend.get('enroll_title') or ''}
                    if pend.get('enroll') else None,
                    'enabled': row.get('enabled') is None or bool(int(row.get('enabled') or 0))})
    out.sort(key=lambda x: float(x.get('at') or 0))
    return out


def confirm_many(store, items, by):
    """Several agents confirmed, each by the fingerprint it asks with -> [{id, name, ok, said}]."""
    out = []
    for it in (items if isinstance(items, list) else [])[:500]:
        if not isinstance(it, dict):
            continue
        try:
            row = target_row(store, int(it.get('id')))
        except (LookupError, TypeError, ValueError):
            out.append({'id': it.get('id'), 'name': '', 'ok': False,
                        'said': 'there is no target with acme-agent of that id'})
            continue
        try:
            confirm(store, row, str(it.get('fp') or ''), by)
            said = 'confirmed'
            pend = state(store, row['id']).get('pending') or {}
            if mode_of(row) == 'passive' and not pend.get('enroll'):
                got = look(store, row, by)
                if got.get('said'):
                    said = 'confirmed - %s' % got['said']
            out.append({'id': row['id'], 'name': row['name'], 'ok': True, 'said': said})
        except PluginError as e:
            out.append({'id': row['id'], 'name': row['name'], 'ok': False, 'said': str(e)})
    return out


def _first_hello(store, row):
    """A passive agent that joined by an enrollment code took its certificate as an active
    join does and then listens: acme asks it how it is - its first answer ends the join."""
    try:
        for _ in range(20):
            time.sleep(3)
            pend = state(store, row['id']).get('pending')
            if not isinstance(pend, dict) or not pend.get('handed'):
                return
            try:
                hello(store, row)
                return
            except (PluginError, OSError, ValueError):
                continue
    finally:
        ASKING.discard(row['id'])


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
    if op == 'enroll':
        # 1.0.120: a server joining with a company enrollment code - its target made
        return enroll_take(store, body, ip)
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
        out = _endpoints_proved(store, secret, dict(c, mode='active'), nonce, {
            'ok': True, 'state': 'done', 'cert_pem': pend['cert'],
            'proof': proof(secret, 'cert', c['id'], hashlib.sha256(
                pend['cert'].encode()).hexdigest(), nonce)})
        # 1.0.119: the code and the confirmed request kept until the agent's first poll with
        # its certificate (poll) - this answer lost, or the agent failing to take it, it asks
        # again and is answered again (it gave away the code once, it used it from the start)
        if not pend.get('handed'):
            pend['handed'] = time.time()
            st['pending'] = pend
            st['last_seen'] = time.time()
            state_put(store, row['id'], st)
            store.add_event('certificates', 'the agent of target %s joined acme (%s) - %s' % (
                row['name'], st.get('agent_id'), st.get('host') or '?'), 'info')
            if mode_of(row) == 'passive' and row['id'] not in ASKING:
                # 1.0.120: joined by an enrollment code, it listens from now on - acme asks it
                ASKING.add(row['id'])
                threading.Thread(target=_first_hello, args=(store, row), daemon=True,
                                 name='agent-hello').start()
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
    if not row or not is_agent_kind(row.get('kind')):
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
    # the agent asks for its certificate renewed - at most once an hour (1.0.116 security: an
    # agent saying so at every poll had a certificate signed, and an event, every few minutes)
    if body.get('renew') and not st.get('renew_wanted') and \
            now - float(st.get('renewed_at') or 0) > RENEW_ASK_S:
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
    # 1.0.118: the policy's hash with every poll - another than the one acme holds (changed
    # on the server, or never said): asked for at once, the pages show it as it is now
    ph = str(facts.get('policy_hash') or '')
    held_pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    if HEX64.match(ph) and ph != held_pol.get('hash') and st.get('cert_fp') and \
            not st.get('pending') and tid not in ASKING:
        ASKING.add(tid)
        threading.Thread(target=_ask_quietly, args=(store, row), daemon=True,
                         name='agent-hello').start()
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
            out['ms'] = max(0, min(int(r['ms']), 86400000))
    except (TypeError, ValueError, OverflowError):      # Infinity, NaN: JSON lets them through
        pass
    for k in ('refused', 'unchanged', 'rolled_back'):
        if r.get(k):
            out[k] = True
    if isinstance(r.get('steps'), list):
        out['steps'] = []
        for s in r['steps'][:200]:
            if isinstance(s, (list, tuple)) and len(s) == 2:
                lv = s[0] if s[0] in ('info', 'ok', 'warn', 'bad') else 'info'
                out['steps'].append([lv, _txt(s[1], 600, lines=True)])
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
            if r.get(k) is not None and math.isfinite(float(r[k])):
                out[k] = float(r[k])
        except (TypeError, ValueError, OverflowError):
            pass
    if isinstance(r.get('cert_fp'), str) and HEX64.match(r['cert_fp']):
        out['cert_fp'] = r['cert_fp']
    return out


def clean_policy(p):
    """The policy as the agent reports it - its shape checked item by item."""
    def s(v, n=300):
        return _txt(v, n)

    def lst(k):
        # 1.0.119: a list the agent says as something else (a number, an object) stopped
        # acme with an error of its own - the poll of that agent failed for good
        v = p.get(k)
        return v if isinstance(v, list) else []
    out = {'hash': s(p.get('hash'), 64), 'files': [], 'units': {}, 'tests': [], 'scripts': [],
           'script_hashes': [], 'from': [], 'connect': [], 'probe': [], 'problems': [],
           'self_update': bool(p.get('self_update')), 'probe_local': bool(p.get('probe_local')),
           'limits': {'files': 20, 'size': 1048576}}
    for f in lst('files')[:200]:
        if isinstance(f, dict) and isinstance(f.get('dir'), str) and f['dir'].startswith('/'):
            try:
                out['files'].append({'dir': s(f['dir'], 1024), 'owner': s(f.get('owner'), 32),
                                     'group': s(f.get('group'), 32),
                                     'mode': int(f.get('mode') or 0) & 0o777})
            except (TypeError, ValueError, OverflowError):
                continue
    units = p.get('units') if isinstance(p.get('units'), dict) else {}
    for u, vs in list(units.items())[:200]:
        if isinstance(vs, list):
            out['units'][s(u, 128)] = [s(v, 30) for v in vs[:8]]
    for t in lst('tests')[:200]:
        if isinstance(t, list) and t:
            out['tests'].append([s(a, 1024) for a in t[:64]])
    for x in lst('scripts')[:200]:
        if isinstance(x, dict) and HEX64.match(str(x.get('sha256') or '')):
            out['scripts'].append({'path': s(x.get('path'), 1024), 'sha256': x['sha256']})
    out['script_hashes'] = [h for h in lst('script_hashes')[:500]
                            if isinstance(h, str) and HEX64.match(h)]
    out['from'] = [s(x, 60) for x in lst('from')[:100]]
    out['connect'] = [s(x, 300) for x in lst('connect')[:100]]
    out['probe'] = [s(x, 300) for x in lst('probe')[:100]]
    out['problems'] = [s(x, 300) for x in lst('problems')[:20]]
    lim = p.get('limits') if isinstance(p.get('limits'), dict) else {}
    for k in ('files', 'size'):
        try:
            out['limits'][k] = max(1, int(lim.get(k) or out['limits'][k]))
        except (TypeError, ValueError, OverflowError):
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
        except (ValueError, UnicodeDecodeError, RecursionError):
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
    pend = st.get('pending') if isinstance(st.get('pending'), dict) else {}
    if mode == 'passive' and pend.get('cert') and pend.get('handed') and pend.get('enroll'):
        # 1.0.120: an agent joined by an enrollment code, passive: it answered over the
        # certificate acme gave it (the one pinned) - so it has it, the join is over
        st.pop('pending', None)
        st.pop('code', None)
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
        st['renewed_at'] = time.time()
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
        status, n, extra = _http_head(head)
        if status != 200:
            while len(extra) < n:
                more = tls.recv(4096)
                if not more:
                    break
                extra += more
            tls.close()
            try:
                said = clean_result(json.loads(extra.decode('utf-8', 'replace') or '{}'))
            except (ValueError, RecursionError):
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


def _http_head(head):
    """(status, Content-Length at most 64 KiB, the bytes after the head) of the agent's answer
    on /v1/tunnel - not believed to be well made (1.0.116 security: a status or a length that
    is no number stopped acme with an error of its own): 0 for what is not a number."""
    line, _, rest = head.partition(b'\r\n')
    top, _, extra = rest.partition(b'\r\n\r\n')
    m = re.match(rb'HTTP/1\.[01] ([0-9]{3})', line or b'')
    status = int(m.group(1)) if m else 0
    n = 0
    for h in top.split(b'\r\n'):
        k, _, v = h.partition(b':')
        if k.strip().lower() == b'content-length' and v.strip().isdigit():
            n = min(int(v.strip()), 65536)
    return status, n, extra


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


def update_candidates(store):
    """The agents a newer one is offered to (1.0.118, "Update all agents"): each with whether
    acme can update it now, and why not - its policy has no `allow self-update`, it does not
    answer, acme has no signed package. The package is always acme's own (the signed agent it
    ships), never one from the internet."""
    try:
        pkg = package(build=False)
    except Exception:                                   # noqa: BLE001
        pkg = None
    now = time.time()
    out = []
    for row in rows(store):
        st = state(store, row['id'])
        if not st.get('cert_fp'):
            continue
        f = update_facts(st, pkg)
        if not f['newer']:
            continue
        mode = mode_of(row)
        seen = float(st.get('last_seen') or 0)
        why = ''
        if not pkg or not pkg.get('signed'):
            why = 'this acme has no signed package of the agent (a source tree)'
        elif not (row.get('enabled') is None or int(row.get('enabled') or 0)):
            why = 'the target is switched off'
        elif st.get('refused'):
            why = 'it is refused'
        elif not f['allowed']:
            why = 'its policy has no allow self-update'
        elif now - seen > QUIET_S:
            why = ('acme cannot reach it' if mode == 'passive' else 'it does not ask acme') + \
                (': %s' % _txt(st.get('last_error'), 200) if st.get('last_error') else
                 ' (not heard from since %s)' % _when(seen or None))
        elif mode == 'active' and not active_on():
            why = 'the agents\' port is off'
        out.append({'id': row['id'], 'name': row['name'], 'mode': mode,
                    'version': st.get('version') or '', 'offered': f['offered'],
                    'ok': not why, 'why': why})
    return out


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
    from acmelib.certs import agent_policy
    agent_policy.design_gone(store, row)


# ---- now and then (the leader) -------------------------------------------------------------------
def rows(store):
    return store.db.rows("SELECT * FROM cert_targets WHERE kind IN %s ORDER BY name" % KINDS_SQL)


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
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:enroll:%'"):
        # 1.0.120: an enrollment code that ended (ran out, revoked) a month ago is gone
        ec = _jload(r['v'], {})
        ec = ec if isinstance(ec, dict) else {}
        rv = ec.get('revoked') if isinstance(ec.get('revoked'), dict) else {}
        try:
            ended = min(float(rv.get('at') or ec.get('until') or 0), float(ec.get('until') or 0))
        except (TypeError, ValueError):
            ended = 0
        if not ended or now - ended > ENROLL_KEEP_S:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
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
            if mode == 'active' and not isinstance(st.get('policy'), dict) and \
                    row['id'] not in ASKING and now - float(st.get('last_seen') or 0) < QUIET_S:
                # an active agent says its policy only with a job: asked once it polls (just
                # joined, or acme started again) - the deployments' forms then judge by it
                ASKING.add(row['id'])
                threading.Thread(target=_ask_quietly, args=(store, row), daemon=True,
                                 name='agent-hello').start()
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


def _ask_quietly(store, row):
    try:
        hello(store, row)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('agent-hello-%s' % row['id'], 'asking the agent of %s: %s' % (
            row['name'], e), 'info', every=3600)
    finally:
        ASKING.discard(row['id'])


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


WIN_PKG_RE = re.compile(r'acme-agent-(\d+\.\d+\.\d+)-windows-x64\.msi\Z')
WIN_NONE = ('the Windows agent (acme-agent-X.Y.Z-windows-x64.msi) comes with a release - a '
            'source tree has none (tools/release.py builds it)')


def package_windows():
    """The Windows agent's MSI a release put beside the program for this version
    (deploy/agent/acme-agent-X.Y.Z-windows-x64.msi, 1.0.120) -> ({name, version, sha256, size,
    signed, product_code, path}, None), or (None, why) - acme never builds one itself."""
    import acmelib
    ver = acmelib.__version__
    name = 'acme-agent-%s-windows-x64.msi' % ver
    path = os.path.join(AGENT_DIR, name)
    if not os.path.isfile(path):
        return None, WIN_NONE
    got = _pkg_facts(path, name, ver, True)
    got['product_code'] = windows_product_code(ver)
    return got, None


def windows_product_code(ver):
    """The MSI's ProductCode of a version (msiexec /x {...}): made from the version the way
    tools/agent_windows.py makes it."""
    import uuid
    ns = uuid.UUID('9b0e7c52-3f6a-4d8e-a1b4-5c7d2e9f0a16')
    return '{%s}' % str(uuid.uuid5(ns, 'acme-agent-windows-x64-' + ver)).upper()


def windows_commands(name):
    """What the pages show to install the MSI (an elevated prompt / PowerShell)."""
    return ['Get-FileHash .\\%s' % name,
            'msiexec /i %s' % name,
            'msiexec /i %s /qn JOINCODE=CODE' % name,
            'acme-agent join CODE']


_FACTS = {}


def _pkg_facts(path, name, ver, signed):
    """(1.0.119: kept by the file's path, time and size - the 4 MB package was read and hashed
    for every agent of the pages' list, at every ask.)"""
    f = os.stat(path)
    key = (path, f.st_mtime_ns, f.st_size, f.st_ino)
    got = _FACTS.get(key)
    if got is None:
        h = hashlib.sha256()
        n = 0
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
                n += len(chunk)
        got = {'sha256': h.hexdigest(), 'size': n}
        if len(_FACTS) > 16:
            _FACTS.clear()
        _FACTS[key] = got
    return {'name': name, 'version': ver, 'sha256': got['sha256'], 'size': got['size'],
            'signed': signed, 'path': path}


def build_package(dest, version, key=None, keys_dir=None, epoch=None):
    """The agent's package - made by the agent's own program (deploy/agent/acme_agent.py
    build_package), which tools/release.py uses too."""
    try:
        return agent_mod().build_package(dest, version, key=key, keys_dir=keys_dir, epoch=epoch)
    except agent_mod().Refused as e:
        raise PluginError(str(e), retry=False)
