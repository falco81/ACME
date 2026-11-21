# -*- coding: utf-8 -*-
"""
A target agent watched more closely (1.0.138, docs/target-agent.md "Watching an agent"). Each of
these is chosen per target on the agent's card and is OFF by default - with all of them off, acme
and the agent talk exactly as before (no job more, no key more in a job):

    A6  the audit chain    the agent keeps a hash-chained log of every job it takes, does or
                           refuses (its policy's line `audit chain`: root decides); acme is told
                           the chain's head with every answer, reads the entries it has not seen
                           and checks each hash, each link and that every job in it is one acme
                           sent - an entry of a job acme never sent, a gap or a chain written
                           anew is an event and an alert until a full administrator looks at it
    A7  anomalies          the agent coming from a new network, its policy changed or widened
                           (a new folder, unit, test, script, connection...), drift from the
                           design saved in acme or a template assigned to it, its clock off, it
                           silent, its version behind, a command key acme does not know
    A8  keys               acme's command key changed on a schedule (the new key announced in a
                           job signed by the old one, proven by itself; the agent takes both for
                           an overlap, then the new one only) and the agent's key for secrets
                           made anew; the age of every key (keys_report)
    B6  what is served     after a deployment and every six hours the agent is asked what the
                           service on the server itself serves (its `probe local` - only where
                           the policy allows it already): "deployed, but the service still serves
                           the old certificate" (a reload forgotten) said on the deployment and
                           the card. Off by default as the others; switched on, only where the
                           policy allows `probe local` already - it takes no permission

What acme keeps (meta - in every backup, on every node; put back by a restore):

    agents:guard:<id>        the target's choices
    agents:audit:<id>        acme's record of its agent's chain: where it checked up to (n, hash),
                             the last entries (the timeline), what did not agree
    agentsent:<id>:<job>     each job acme sent to it while the chain is compared (30 days)
    agents:anom:<id>         what acme took as the agent's usual (policy, networks) and what
                             was seen since
    agents:served:<id>       what each deployment's service served when last asked
    agents:cmdkey:<fp>       an earlier command key (sealed), kept while an agent pins it
    agents:cmdbase           the command key every agent joined before the first change pins
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time

from acmelib import engine as E
from acmelib.plugins.base import PluginError

M_OPT = 'agents:guard:%d'
M_AUDIT = 'agents:audit:%d'
M_ANOM = 'agents:anom:%d'
M_SERVED = 'agents:served:%d'
M_CMDKEY = 'agents:cmdkey:%s'
M_CMDBASE = 'agents:cmdbase'
SENT = 'agentsent:%d:%s'

DEFAULTS = {'audit': False, 'anomaly': False, 'rotate': False, 'rotate_days': 90,
            'health': 'off'}
ROTATE_DAYS = (7, 730)
OVERLAP_S = 3 * 86400           # the agent takes the old command key this long after the change
SENT_KEEP_S = 30 * 86400
TIMELINE = 200                  # entries of the chain kept for the card
PROBLEMS = 50
FETCH_MOST = 200
FETCH_ROUNDS = 5
FETCH_EVERY_S = 1800            # the chain read at least this often (the leader) while it grows
FETCH_LAG = 20                  # ...or once this many entries are not read yet
HEALTH_EVERY_S = 6 * 3600       # what is served asked this often
HEALTH_AFTER_S = 20             # ...and this long after a deployment (its reload done)
HEALTH_MOST = 10                # deployments asked of one agent at a time
SKEW_WARN = 60
BEFORE_S = 15                   # an entry this soon after the chain was switched on in acme:
                                # a job signed before acme kept them (not "unknown"); the jobs
                                # queued for an active agent then are kept when it is switched on
SERVER_OPS = ('policy', 'pin', 'conf', 'chain', 'join', 'forget', 'init', 'root')
LOCK = threading.RLock()
BUSY = set()                    # (what, target id) under way on this node
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _G():
    from acmelib.certs import agents
    return agents


def _jl(text, default=None):
    try:
        v = json.loads(text) if text else default
    except (TypeError, ValueError):
        return default
    return v


def _obj(store, key):
    v = _jl(store.get_meta(key), {})
    return v if isinstance(v, dict) else {}


def _put(store, key, obj):
    store.set_meta(key, json.dumps(obj, sort_keys=True))


def _txt(v, most=300):
    return _G()._txt(v, most)


def _event(store, words, level='info', who='', **fields):
    """An event with the fields isemon and the SIEM read (action=agent_..., target=...)."""
    f = {'target_kind': 'agent', 'result': 'ok' if level == 'info' else
         ('failed' if level == 'bad' else 'warn')}
    f.update({k: v for k, v in fields.items() if v not in (None, '')})
    with E.event_with(**f):
        store.add_event('certificates', words, level, who=who)


def _busy(what, tid):
    with LOCK:
        if (what, tid) in BUSY:
            return False
        BUSY.add((what, tid))
        return True


def _done(what, tid):
    with LOCK:
        BUSY.discard((what, tid))


def _later(what, tid, fn, *args):
    """fn(*args) in a thread of its own - once at a time for a target on this node."""
    if not _busy(what, tid):
        return False

    def run():
        try:
            fn(*args)
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('agent-guard-%s-%s' % (what, tid), 'the agent %s: %s' % (what, e),
                          'info', every=3600)
        finally:
            _done(what, tid)
    threading.Thread(target=run, daemon=True, name='agent-' + what).start()
    return True


# ---- the target's choices ------------------------------------------------------------------------
def opts(store, tid):
    got = _obj(store, M_OPT % int(tid))
    out = dict(DEFAULTS)
    for k in ('audit', 'anomaly', 'rotate'):
        out[k] = bool(got.get(k))
    try:
        out['rotate_days'] = max(ROTATE_DAYS[0], min(ROTATE_DAYS[1], int(
            got.get('rotate_days') or DEFAULTS['rotate_days'])))
    except (TypeError, ValueError):
        pass
    out['health'] = 'on' if got.get('health') == 'on' else 'off'
    for k in ('at', 'by', 'audit_at', 'anomaly_at', 'rotate_at'):
        if got.get(k):
            out[k] = got[k]
    return out


WORDS_ON = {'audit': ('acme compares the audit chain of the agent of target %s (switched on by %s)',
                      'acme no longer compares the audit chain of the agent of target %s '
                      '(switched off by %s)'),
            'anomaly': ('acme watches the agent of target %s for anomalies (switched on by %s)',
                        'acme no longer watches the agent of target %s for anomalies (switched '
                        'off by %s)'),
            'health': ('acme asks what the services of the agent of target %s serve (switched on '
                       'by %s)',
                       'acme no longer asks what the services of the agent of target %s serve '
                       '(switched off by %s)'),
            'rotate': ('the keys of the agent of target %s are changed on a schedule (switched '
                       'on by %s)',
                       'the keys of the agent of target %s are no longer changed on a schedule '
                       '(switched off by %s)')}


def set_opts(store, row, body, by):
    """The choices changed (a full administrator): {audit, anomaly, rotate, rotate_days,
    health} - each one only when given."""
    if not isinstance(body, dict):
        raise ValueError('the choices are an object')
    key = M_OPT % int(row['id'])
    have = _obj(store, key)
    now = time.time()
    changed = []
    for k in ('audit', 'anomaly', 'rotate'):
        if k in body:
            v = body[k]
            if not isinstance(v, bool):
                raise ValueError('%s is true or false' % k)
            if bool(have.get(k)) != v:
                have[k] = v
                have[k + '_at'] = now
                changed.append(k)
    if 'rotate_days' in body:
        try:
            d = int(body['rotate_days'])
        except (TypeError, ValueError):
            raise ValueError('rotate_days is a number of days')
        if not ROTATE_DAYS[0] <= d <= ROTATE_DAYS[1]:
            raise ValueError('the keys are changed every %d to %d days' % ROTATE_DAYS)
        have['rotate_days'] = d
    if 'health' in body:
        if body['health'] not in ('on', 'off'):
            raise ValueError('health is on or off')
        if (have.get('health') == 'on') != (body['health'] == 'on'):
            changed.append('health')
        have['health'] = body['health']
    have['at'], have['by'] = now, _txt(by, 120)
    _put(store, key, have)
    for k in changed:
        if k == 'audit':
            # compared from now on: what the agent says first is taken as known - and the jobs
            # waiting for an active agent's poll now are acme's
            _put(store, M_AUDIT % int(row['id']), {'enabled_at': now} if have[k] else {})
            if have[k]:
                for r in store.db.rows('SELECT k FROM meta WHERE k LIKE ?',
                                       ('agentq:%d:%%' % int(row['id']),)):
                    store.set_meta(SENT % (int(row['id']), r['k'].rsplit(':', 1)[1]),
                                   json.dumps({'op': '?', 'at': now, 'node': E.node_name()}))
        if k == 'health' and have.get('health') != 'on':
            store.db.run('DELETE FROM meta WHERE k = ?', (M_SERVED % int(row['id']),))
        if k == 'anomaly':
            store.db.run('DELETE FROM meta WHERE k = ?', (M_ANOM % int(row['id']),))
            if have[k]:
                evaluate(store, row, _G().state(store, row['id']))
        on = have.get('health') == 'on' if k == 'health' else bool(have[k])
        _event(store, WORDS_ON[k][0 if on else 1] % (row['name'], by), who=by,
               action='agent_guard', target=row['name'], what=k, on=1 if on else 0)
    return opts(store, row['id'])


def forget(store, row, gone=False):
    """The agent forgotten (a new one joins with new keys and a new chain): what acme kept of
    the old one goes; the choices stay - unless the target is gone too."""
    tid = int(row['id'])
    for k in (M_AUDIT % tid, M_ANOM % tid, M_SERVED % tid) + ((M_OPT % tid,) if gone else ()):
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
    store.db.run('DELETE FROM meta WHERE k LIKE ?', ('agentsent:%d:%%' % tid,))


def joined_anew(store, row):
    """hunt R f1: an agent joined (again) on the target - a new identity, often a new install
    with a new, empty chain: acme's record of the chain before starts again (its first head is
    taken as known), or it said "entries were taken away" / "written anew" of every reinstall."""
    tid = int(row['id'])
    if opts(store, tid)['audit']:
        _put(store, M_AUDIT % tid, {'enabled_at': time.time()})
    else:
        store.db.run('DELETE FROM meta WHERE k = ?', (M_AUDIT % tid,))


# ---- what the agent says of itself (hello) ------------------------------------------------------
def seen_hello(st, got, store=None):
    """1.0.138: what it can do, the command key it pins, when its key for secrets was made."""
    could = can(st, 'cmdkey')
    feats = got.get('features')
    if isinstance(feats, list):
        st['features'] = [_txt(x, 30) for x in feats[:20] if isinstance(x, str)]
    else:
        st['features'] = []
    if st.get('key_said') and not could and can(st, 'cmdkey'):
        # hunt R f1: "too old to change keys" was never tried again once it was updated
        st['key_said'] = ''
    fp = got.get('cmd_fp')
    if isinstance(fp, str) and HEX64.match(fp):
        st['agent_cmd_fp'] = fp
        if store is not None:
            # hunt R f1: the answer of `cmdkey` lost (a failover, a timeout) after the agent took
            # the new key - acme went on signing with the old one, refused for good once the
            # overlap was over. The key it says it pins, when acme has it, is the one to sign with.
            try:
                if fp != pinned_fp(store, st) and fp in known_fps(store):
                    st['cmd_fp'] = fp
            except Exception:                           # noqa: BLE001
                pass
    if isinstance(got.get('enc_at'), (int, float)) and got['enc_at'] > 0:
        st['enc_at'] = float(got['enc_at'])


def can(st, feature):
    return feature in (st.get('features') or [])


# ---- A6: the audit chain ------------------------------------------------------------------------
def chain_canon(e):
    """The bytes an entry's hash is taken of - as the agent takes them (chain_canon there)."""
    return json.dumps({k: v for k, v in e.items() if k != 'h'}, sort_keys=True,
                      separators=(',', ':'), ensure_ascii=True).encode('ascii')


def parse_entry(line):
    if not isinstance(line, str) or len(line) > 8192:
        return None
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if not isinstance(e, dict) or not isinstance(e.get('n'), int) or isinstance(e.get('n'), bool) \
            or not HEX64.match(str(e.get('h') or '')) or not HEX64.match(str(e.get('prev') or '')):
        return None
    return e


def sent(store, row, jid, op):
    """A job acme sends to the agent - kept while its chain is compared."""
    try:
        if opts(store, row['id'])['audit']:
            store.set_meta(SENT % (int(row['id']), jid), json.dumps(
                {'op': str(op)[:40], 'at': time.time(), 'node': E.node_name()}))
    except Exception:                                   # noqa: BLE001
        pass


def clean_head(a):
    if not isinstance(a, dict):
        return None
    try:
        n = int(a.get('n'))
    except (TypeError, ValueError, OverflowError):
        return None
    h = str(a.get('h') or '')
    if n < 0 or n > 10 ** 12 or not HEX64.match(h):
        return None
    out = {'n': n, 'h': h, 'on': bool(a.get('on', True))}
    if a.get('broken'):
        out['broken'] = True
    return out


def _problem(store, row, st, kind, words, n=None):
    """Something of the chain that does not agree: kept until a full administrator has looked,
    said once as an event (and an alert while it is kept)."""
    probs = st.setdefault('problems', [])
    if any(p.get('kind') == kind and p.get('n') == n for p in probs):
        return
    probs.append({'kind': kind, 'words': _txt(words, 400), 'n': n, 'at': time.time()})
    st['problems'] = probs[-PROBLEMS:]
    _event(store, 'the audit chain of the agent of target %s does not agree with acme: %s' % (
        row['name'], words), 'bad', action='agent_audit_mismatch', target=row['name'], what=kind)


def answered(store, row, op, got):
    """Every answer of the agent: the chain's head it says, against what acme knows."""
    head = clean_head(got.get('audit')) if isinstance(got, dict) else None
    o = opts(store, row['id'])
    if not o['audit']:
        return
    key = M_AUDIT % int(row['id'])
    fetch = False
    with LOCK:
        st = _obj(store, key)
        if head is None:
            if op in ('hello', 'policy') and got.get('ok'):
                pol = got.get('policy') if isinstance(got.get('policy'), dict) else {}
                st['agent_off'] = not pol.get('audit_chain')
                st['said_at'] = time.time()
                _put(store, key, st)
            return
        st['agent_off'] = False
        st['said_at'] = time.time()
        was = st.get('head') if isinstance(st.get('head'), dict) else {}
        if head['n'] >= int(was.get('n') or 0):
            st['head'] = {'n': head['n'], 'h': head['h'], 'at': time.time()}
        if 'verified_n' not in st:
            # the first head acme hears: taken as known (what is before it was not watched)
            st.update(base_n=head['n'], verified_n=head['n'], verified_h=head['h'],
                      verified_at=time.time(), base_at=time.time())
        known = {e.get('n'): e.get('h') for e in st.get('entries') or []}
        if head['n'] == st.get('verified_n'):
            known[head['n']] = st.get('verified_h')
        if head['n'] in known and known[head['n']] and known[head['n']] != head['h']:
            _problem(store, row, st, 'rewritten', 'entry %d is now another one than acme read '
                     '- the chain was written anew' % head['n'], head['n'])
        if head.get('broken'):
            _problem(store, row, st, 'broken', 'the last line of the chain is no entry',
                     head['n'])
        _put(store, key, st)
        fetch = op != 'audit' and head['n'] > int(st.get('verified_n') or 0) and (
            head['n'] - int(st.get('verified_n') or 0) >= FETCH_LAG or
            op in ('deploy', 'keygen', 'update', 'cmdkey', 'enckey', 'discover'))
    if fetch:
        _later('audit', int(row['id']), read_chain, store, row)


def _mark(store, row, st, e):
    """Whose an entry is: acme's job, done on the server itself, a job refused before it was
    read, a job from before acme compared - or a job acme never sent."""
    jid = str(e.get('job') or '')
    if jid:
        if store.get_meta(SENT % (int(row['id']), jid)):
            return 'acme'
        if float(e.get('ts') or 0) < float(st.get('enabled_at') or st.get('base_at') or 0) + \
                BEFORE_S:
            return 'before'
        _problem(store, row, st, 'unknown', 'the agent did a job acme never sent (job %s, %s, '
                 'entry %d) - somebody else signed it with acme\'s command key' % (
                     jid[:24], _txt(e.get('op'), 40), e['n']), e['n'])
        return 'unknown'
    if str(e.get('op') or '') in SERVER_OPS:
        return 'server'
    return 'refused' if not e.get('ok', True) else 'server'


def read_chain(store, row, by='', recheck=False):
    """The entries of the chain acme has not read, checked: each hash, each link, each job -
    from the last one it read (that one again: still the same?). `recheck`: from the oldest
    one it keeps (every one of them still the same, still linked: a chain written anew from an
    entry acme read is found). -> the record (agents:audit)."""
    G = _G()
    key = M_AUDIT % int(row['id'])
    for _round in range(FETCH_ROUNDS):
        st = _obj(store, key)
        if 'verified_n' not in st:
            G.call(store, row, 'hello', {}, timeout=30)
            st = _obj(store, key)
            if 'verified_n' not in st:
                return st
        known = {e.get('n'): e.get('h') for e in st.get('entries') or []}
        known[int(st['verified_n'])] = st.get('verified_h')
        frm = max(1, int(st['verified_n']))
        if recheck and _round == 0:
            frm = max(1, min([n for n in known if isinstance(n, int)] or [frm]))
        got = G.call(store, row, 'audit', {'from': frm, 'most': FETCH_MOST}, timeout=60)
        with LOCK:
            st = _obj(store, key)
            if not got.get('ok'):
                st['agent_off'] = bool(got.get('needs')) or 'audit chain' in str(got.get('said'))
                st['read_said'] = _txt(got.get('said'), 300)
                st['read_at'] = time.time()
                _put(store, key, st)
                return st
            lines = got.get('entries') if isinstance(got.get('entries'), list) else []
            ver_n = int(st['verified_n'])
            prev_h, want = st.get('verified_h'), ver_n + 1
            head = clean_head(got.get('audit'))
            timeline = list(st.get('entries') or [])
            took = 0
            last_old = None
            if head and head['n'] < want - 1 or (not lines and head and head['n'] < want):
                _problem(store, row, st, 'shorter', 'the chain ends at entry %d - acme read it '
                         'up to entry %d: entries were taken away' % (head['n'], want - 1),
                         head['n'])
                st.update(verified_n=head['n'], verified_h=head['h'], verified_at=time.time())
            for line in lines:
                e = parse_entry(line)
                if e is None:
                    _problem(store, row, st, 'unreadable', 'an entry acme cannot read after '
                             'entry %d' % (want - 1), want)
                    break
                if e['n'] <= ver_n and not took:
                    # read before: still the very same entry, still linked to the one before
                    if known.get(e['n']) and known[e['n']] != e['h']:
                        _problem(store, row, st, 'rewritten', 'entry %d is not the one acme read '
                                 '- the chain was written anew' % e['n'], e['n'])
                    elif last_old is not None and last_old['n'] + 1 == e['n'] and \
                            e['prev'] != last_old['h']:
                        _problem(store, row, st, 'rewritten', 'entry %d does not follow entry %d '
                                 '- the chain was written anew' % (e['n'], last_old['n']), e['n'])
                    elif hashlib.sha256(chain_canon(e)).hexdigest() != e['h']:
                        _problem(store, row, st, 'changed', 'entry %d is not what its hash says '
                                 '- it was changed' % e['n'], e['n'])
                    last_old = e
                    continue
                if e['n'] != want:
                    _problem(store, row, st, 'gap', 'entries %d to %d are missing' % (
                        want, e['n'] - 1) if e['n'] > want else 'entry %d comes again after '
                        'entry %d' % (e['n'], want - 1), want)
                elif e['prev'] != prev_h:
                    _problem(store, row, st, 'rewritten', 'entry %d does not follow entry %d '
                             'acme read - the chain was written anew' % (e['n'], e['n'] - 1),
                             e['n'])
                if hashlib.sha256(chain_canon(e)).hexdigest() != e['h']:
                    _problem(store, row, st, 'changed', 'entry %d is not what its hash says - '
                             'it was changed' % e['n'], e['n'])
                mark = _mark(store, row, st, e)
                timeline.append({'n': e['n'], 'h': e['h'], 'ts': e.get('ts'),
                                 'op': _txt(e.get('op'), 40), 'job': _txt(e.get('job'), 64),
                                 'ok': bool(e.get('ok', True)), 'said': _txt(e.get('said'), 240),
                                 'mark': mark})
                prev_h, want = e['h'], e['n'] + 1
                took += 1
            if took:
                st.update(verified_n=want - 1, verified_h=prev_h)
            st['verified_at'] = time.time()
            if recheck:
                st['rechecked_at'] = time.time()
            st['entries'] = timeline[-TIMELINE:]
            st['read_at'] = time.time()
            st['read_said'] = ''
            if head and head['n'] >= int((st.get('head') or {}).get('n') or 0):
                st['head'] = {'n': head['n'], 'h': head['h'], 'at': time.time()}
            _put(store, key, st)
        if len(lines) < FETCH_MOST:
            return st
    return _obj(store, key)


def ack(store, row, what, by):
    """A full administrator has looked: what did not agree is put away, and what is there now
    is the agent's usual from here."""
    tid = int(row['id'])
    if what == 'audit':
        st = _obj(store, M_AUDIT % tid)
        n = len(st.get('problems') or [])
        st['problems'] = []
        st['acked'] = {'at': time.time(), 'by': _txt(by, 120), 'n': n}
        _put(store, M_AUDIT % tid, st)
        _event(store, 'what did not agree in the audit chain of the agent of target %s was looked '
               'at by %s (%d)' % (row['name'], by, n), who=by, action='agent_audit_acked',
               target=row['name'])
    elif what == 'anomaly':
        an = _obj(store, M_ANOM % tid)
        n = len(an.get('seen') or [])
        store.db.run('DELETE FROM meta WHERE k = ?', (M_ANOM % tid,))
        evaluate(store, row, _G().state(store, tid))
        an = _obj(store, M_ANOM % tid)
        an['acked'] = {'at': time.time(), 'by': _txt(by, 120), 'n': n}
        _put(store, M_ANOM % tid, an)
        _event(store, 'the anomalies of the agent of target %s were looked at by %s (%d) - what '
               'it is now is its usual' % (row['name'], by, n), who=by,
               action='agent_anomaly_acked', target=row['name'])
    else:
        raise ValueError('what: audit or anomaly')


def audit_view(store, row, st, full=False):
    o = opts(store, row['id'])
    a = _obj(store, M_AUDIT % int(row['id']))
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    joined = bool(st.get('cert_fp'))
    if not o['audit']:
        state = 'off'
    elif joined and st.get('features') is not None and not can(st, 'audit-chain'):
        state = 'unsupported'
    elif a.get('problems'):
        state = 'mismatch'
    elif a.get('agent_off') or (pol and not pol.get('audit_chain') and not a.get('head')):
        state = 'agent_off'
    elif a.get('head'):
        state = 'ok' if int(a['head'].get('n') or 0) <= int(a.get('verified_n') or 0) \
            else 'behind'
    else:
        state = 'waiting'
    out = {'on': o['audit'], 'state': state, 'agent_on': bool(pol.get('audit_chain')),
           'supported': can(st, 'audit-chain') if st.get('features') is not None else None,
           'n': (a.get('head') or {}).get('n'), 'verified_n': a.get('verified_n'),
           'base_n': a.get('base_n'), 'verified_at': a.get('verified_at'),
           'read_at': a.get('read_at'), 'problems': len(a.get('problems') or []),
           'line': 'audit chain', 'command': 'acme-agent audit on'}
    if full:
        out['entries'] = list(reversed(a.get('entries') or []))
        out['problem_list'] = list(reversed(a.get('problems') or []))
        out['acked'] = a.get('acked')
        out['read_said'] = a.get('read_said') or ''
        out['head_h'] = (a.get('head') or {}).get('h')
    return out


# ---- A7: anomalies ------------------------------------------------------------------------------
def policy_items(pol):
    """What a policy allows, item by item (the words of its lines) - to say what is new."""
    if not isinstance(pol, dict):
        return []
    out = []
    for f in pol.get('files') or []:
        if isinstance(f, dict):
            out.append('file %s %s:%s %04o' % (f.get('dir'), f.get('owner'), f.get('group'),
                                               int(f.get('mode') or 0)))
    for u, vs in sorted((pol.get('units') or {}).items()):
        for v in vs or []:
            out.append('unit %s %s' % (u, v))
    for t in pol.get('tests') or []:
        out.append('test %s' % ' '.join(str(x) for x in t))
    for s in pol.get('scripts') or []:
        if isinstance(s, dict):
            out.append('script %s %s' % (s.get('path'), str(s.get('sha256'))[:16]))
    for h in pol.get('script_hashes') or []:
        out.append('script-hash %s' % str(h)[:16])
    for c in pol.get('connect') or []:
        out.append('connect %s' % c)
    for c in pol.get('probe') or []:
        out.append('probe %s' % c)
    if pol.get('probe_local'):
        out.append('probe local')
    if pol.get('self_update'):
        out.append('self-update')
    for k in pol.get('discover') or []:
        out.append('discover %s' % k)
    if pol.get('store'):
        out.append('store')
    if pol.get('rdp'):
        out.append('rdp')
    for s in pol.get('iis') or []:
        out.append('iis %s' % s)
    for r, extra in sorted((pol.get('roles') or {}).items()):
        out.append('role %s %s' % (r, ','.join(extra or [])))
    for a in pol.get('key_read') or []:
        out.append('key-read %s' % a)
    for a in pol.get('adcs') or []:
        if isinstance(a, dict):
            out.append('adcs %s %s' % (a.get('ca'), ','.join(a.get('templates') or [])))
    if pol.get('adcs_read'):
        out.append('adcs-read')
    return sorted(set(out))


def _wider(base, pol):
    """The items a policy allows now that it did not - and its limits raised, `allow from`
    taken away (from somewhere to anywhere)."""
    added = [x for x in policy_items(pol) if x not in set(base.get('items') or [])]
    lim, was = (pol or {}).get('limits') or {}, base.get('limits') or {}
    for k in ('files', 'size'):
        try:
            if int(lim.get(k) or 0) > int(was.get(k) or 0) > 0:
                added.append('limit %s %s (was %s)' % (k, lim.get(k), was.get(k)))
        except (TypeError, ValueError):
            pass
    if base.get('from') and not (pol or {}).get('from'):
        added.append('from anywhere (was %s)' % ', '.join(base['from'][:3]))
    return added


def network_of(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return ''
    if getattr(a, 'ipv4_mapped', None):
        a = a.ipv4_mapped
    return str(ipaddress.ip_network('%s/%d' % (a, 24 if a.version == 4 else 64), strict=False))


def _base_of(st):
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    out = {'at': time.time()}
    if pol:
        out.update(hash=str(pol.get('hash') or ''), items=policy_items(pol),
                   limits=dict(pol.get('limits') or {}), **{'from': list(pol.get('from') or [])})
    net = network_of(st.get('last_ip') or '')
    out['nets'] = [net] if net else []
    return out


def evaluate(store, row, st):
    """What the agent is now against its usual (only with anomalies watched): a policy changed
    or widened, a new network - each kept and said once (an event; an alert while kept)."""
    if not opts(store, row['id'])['anomaly'] or not st.get('cert_fp'):
        return
    key = M_ANOM % int(row['id'])
    with LOCK:
        an = _obj(store, key)
        base = an.get('base') if isinstance(an.get('base'), dict) else None
        changed = False
        if base is None:
            an['base'] = _base_of(st)
            _put(store, key, an)
            return
        seen = an.setdefault('seen', [])
        pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
        if pol and not base.get('hash'):
            base.update({k: v for k, v in _base_of(st).items() if k != 'nets'})
            changed = True
        elif pol and pol.get('hash') and pol['hash'] != base.get('hash') and \
                not any(s.get('hash') == pol['hash'] for s in seen):
            wide = _wider(base, pol)
            gone = [x for x in base.get('items') or [] if x not in set(policy_items(pol))]
            kind = 'widened' if wide else 'policy'
            words = ('the policy of the agent of target %s was widened on the server: %s' % (
                row['name'], '; '.join(wide[:6])) if wide else
                'the policy of the agent of target %s changed on the server (%s)' % (
                    row['name'], '; '.join(('- ' + x) for x in gone[:6]) or
                    'its hash %s…' % pol['hash'][:12]))
            seen.append({'kind': kind, 'level': 'bad' if wide else 'warn', 'at': time.time(),
                         'hash': pol['hash'], 'added': wide[:20], 'removed': gone[:20],
                         'words': _txt(words, 500)})
            _event(store, words, 'bad' if wide else 'warn', action='agent_anomaly',
                   target=row['name'], what=kind)
            changed = True
        net = network_of(st.get('last_ip') or '')
        if net and net not in (base.get('nets') or []) and \
                not any(s.get('net') == net for s in seen):
            if not base.get('nets'):
                base['nets'] = [net]            # the first it was heard from: its usual
            else:
                words = 'the agent of target %s comes from a new network: %s (its usual: %s)' % (
                    row['name'], st.get('last_ip'), ', '.join(base['nets'][:4]))
                seen.append({'kind': 'network', 'level': 'warn', 'at': time.time(), 'net': net,
                             'ip': _txt(st.get('last_ip'), 45), 'words': _txt(words, 500)})
                _event(store, words, 'warn', action='agent_anomaly', target=row['name'],
                       what='network')
            changed = True
        if changed:
            an['seen'] = seen[-PROBLEMS:]
            _put(store, key, an)


def _template(store, row, st):
    """The fleet's policy template the agent should follow (fleet.py: its own, or its group's)
    against the policy it last said - {name, state, added, removed, via} or None (no template,
    or no fleet in this acme)."""
    try:
        from acmelib.certs import fleet
    except ImportError:
        return None
    fn = getattr(fleet, 'drift', None)
    if not callable(fn):
        return None
    try:
        d = fn(store, row, st.get('policy') if isinstance(st.get('policy'), dict) else None)
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(d, dict) or d.get('state') not in ('matches', 'differs', 'unknown',
                                                          'other'):
        return None
    t = d.get('template') if isinstance(d.get('template'), dict) else {}
    return {'name': _txt(t.get('title') or t.get('ref') or '?', 120), 'state': d['state'],
            'via': _txt(t.get('via'), 10), 'group': _txt(t.get('group'), 120),
            'added': [_txt(x, 300) for x in (d.get('missing') or [])[:20]],
            'removed': [_txt(x, 300) for x in (d.get('extra') or [])[:20]]}


def anomalies(store, row, st, now=None):
    """[{kind, level, words, at?, live}] - what is kept (until looked at) and what is so now."""
    now = now or time.time()
    G = _G()
    an = _obj(store, M_ANOM % int(row['id']))
    out = [dict(s, live=False) for s in reversed(an.get('seen') or [])]
    if not st.get('cert_fp'):
        return out
    seen = float(st.get('last_seen') or 0)
    if now - seen > G.QUIET_S:
        out.append({'kind': 'quiet', 'level': 'warn', 'live': True, 'at': seen or None,
                    'words': 'the agent of target %s has not been heard from since %s' % (
                        row['name'], G._when(seen) if seen else 'it joined')})
    skew = st.get('skew')
    if isinstance(skew, (int, float)) and abs(skew) > SKEW_WARN and \
            now - float(st.get('skew_at') or 0) < 3600:
        out.append({'kind': 'clock', 'level': 'bad' if abs(skew) > 120 else 'warn', 'live': True,
                    'words': 'the clock of the server of target %s is %d s %s acme\'s' % (
                        row['name'], abs(skew), 'ahead of' if skew > 0 else 'behind')})
    try:
        u = G.update_facts(st)
    except Exception:                                   # noqa: BLE001
        u = {}
    if u.get('newer'):
        out.append({'kind': 'version', 'level': 'warn', 'live': True,
                    'words': 'the agent of target %s runs %s - %s is offered' % (
                        row['name'], st.get('version') or '?', u.get('offered'))})
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    if pol:
        try:
            from acmelib.certs import agent_policy
            d = agent_policy.design_summary(store, row, pol)
        except Exception:                               # noqa: BLE001
            d = None
        if d and d.get('state') == 'differs':
            out.append({'kind': 'drift', 'level': 'warn', 'live': True,
                        'words': 'the policy of the agent of target %s differs from its design '
                                 'saved in acme (%d to add, %d not in the design)' % (
                                     row['name'], d.get('added') or 0, d.get('removed') or 0)})
        t = _template(store, row, st)
        if t and t['state'] == 'differs':
            out.append({'kind': 'template', 'level': 'warn', 'live': True,
                        'words': 'the policy of the agent of target %s differs from its template '
                                 '%s' % (row['name'], t['name']),
                        'added': t['added'], 'removed': t['removed']})
    unknown = unknown_cmd_key(store, st)
    if unknown:
        out.append({'kind': 'cmdkey', 'level': 'bad', 'live': True,
                    'words': 'the agent of target %s pins a command key acme does not have '
                             '(%s…) - acme\'s jobs are refused once its overlap ends' % (
                                 row['name'], unknown[:16])})
    return out


def anomaly_view(store, row, st):
    o = opts(store, row['id'])
    if not o['anomaly']:
        return {'on': False, 'items': []}
    an = _obj(store, M_ANOM % int(row['id']))
    items = anomalies(store, row, st)
    return {'on': True, 'items': items, 'acked': an.get('acked'),
            'base_at': (an.get('base') or {}).get('at'),
            'nets': (an.get('base') or {}).get('nets') or [],
            'template': _template(store, row, st),
            'worst': 'bad' if any(i['level'] == 'bad' for i in items) else
                     ('warn' if items else 'ok')}


# ---- A8: the keys --------------------------------------------------------------------------------
def _cmd_current(store):
    G = _G()
    k = G.cmd_key(store)
    meta = E._meta_obj(store, G.M_CMD)
    return k, float(meta.get('at') or 0)


def _seed_of(store, fp):
    got = _obj(store, M_CMDKEY % fp)
    if not got.get('seed'):
        return None
    plain = E.unseal_secret(got['seed'], M_CMDKEY % fp)
    if not plain:
        return None
    seed = base64.b64decode(plain)
    return seed if len(seed) == 32 else None


def pinned_fp(store, st):
    """The fingerprint of acme's command key an agent pins (as far as acme knows)."""
    fp = str(st.get('cmd_fp') or '')
    if HEX64.match(fp):
        return fp
    base = str(store.get_meta(M_CMDBASE) or '')
    if HEX64.match(base):
        return base
    return _cmd_current(store)[0]['fp']


def seed_for(store, st):
    """The seed to sign this agent's jobs with: the command key it pins - None: acme's current
    one (every agent before a change was ever made)."""
    fp = str(st.get('cmd_fp') or '') or str(store.get_meta(M_CMDBASE) or '')
    if not HEX64.match(fp):
        return None
    cur = _cmd_current(store)[0]
    if fp == cur['fp']:
        return None
    seed = _seed_of(store, fp)
    if seed is None:
        E.log_sparing('agent-cmdkey-%s' % fp[:12], 'the command key %s… an agent pins is not '
                      'kept (retired?) - its jobs are signed with the current one' % fp[:16],
                      'warn', every=3600)
    return seed


def known_fps(store):
    cur = _cmd_current(store)[0]['fp']
    out = {cur}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:cmdkey:%'"):
        v = _jl(r['v'], {})
        if isinstance(v, dict) and v.get('seed'):
            out.add(r['k'].rsplit(':', 1)[1])
    return out


def unknown_cmd_key(store, st):
    fp = str(st.get('agent_cmd_fp') or '')
    if not HEX64.match(fp):
        return ''
    try:
        return '' if fp in known_fps(store) else fp
    except Exception:                                   # noqa: BLE001
        return ''


def cmd_new(store, by):
    """A new command key for acme: the one in use kept (sealed, agents:cmdkey:<fp>) while any
    agent pins it; new joins pin the new one; each agent moves to it (cmd_move)."""
    G = _G()
    with G.LOCK:
        cur, at = _cmd_current(store)
        if not store.get_meta(M_CMDBASE):
            store.set_meta(M_CMDBASE, cur['fp'])
        if not _obj(store, M_CMDKEY % cur['fp']).get('seed'):
            _put(store, M_CMDKEY % cur['fp'], {
                'seed': E.seal_secret(G._b64(cur['seed']), M_CMDKEY % cur['fp']),
                'at': at or None, 'replaced_at': time.time(), 'fp': cur['fp']})
        seed = secrets.token_bytes(32)
        pub = E.ed25519_public(seed)
        fp = hashlib.sha256(pub).hexdigest()
        # the new one kept in a row of its own too: two nodes changing it at once each keep
        # theirs - an agent moved to the one that lost is still signed for
        _put(store, M_CMDKEY % fp, {'seed': E.seal_secret(G._b64(seed), M_CMDKEY % fp),
                                    'at': time.time(), 'fp': fp})
        store.set_meta(G.M_CMD, json.dumps({'seed': E.seal_secret(G._b64(seed), G.M_CMD),
                                            'at': time.time(), 'prev': cur['fp']}))
    _event(store, 'acme\'s command key was changed by %s: %s… (the one before, %s…, is kept while '
           'an agent pins it)' % (by, fp[:16], cur['fp'][:16]), who=by, action='agent_cmdkey_new')
    return fp


def cmd_move(store, row, by):
    """The agent moved to acme's current command key: a job `cmdkey` signed with the key it
    pins now, the new key proven by itself. -> the new fingerprint."""
    G = _G()
    st = G.state(store, row['id'])
    if not st.get('cert_fp'):
        raise PluginError('the agent of %s has not joined' % row['name'], retry=False)
    cur = _cmd_current(store)[0]
    old = pinned_fp(store, st)
    if old == cur['fp']:
        return cur['fp']
    pub = G._b64(cur['public'])
    words = ('%s cmdkey\n%s\n%s\n%s' % (G.PROTO, st.get('agent_id'), pub, old)).encode('utf-8')
    got = G.call(store, row, 'cmdkey', {'pub': pub, 'fp': cur['fp'], 'overlap_s': OVERLAP_S,
                                        'proof': G._b64(E.ed25519_sign(cur['seed'], words))},
                 timeout=60)
    if not got.get('ok'):
        said = _txt(got.get('said'), 300)
        if 'not an operation' in said:
            said = TOO_OLD
        st = G.state(store, row['id'])
        st['key_said'] = said
        G.state_put(store, row['id'], st)
        raise PluginError(said or 'the agent refused the new command key', retry=False)
    st = G.state(store, row['id'])
    st.update(cmd_fp=cur['fp'], cmd_prev_fp=old, cmd_moved_at=time.time(),
              cmd_prev_until=time.time() + OVERLAP_S, key_said='')
    G.state_put(store, row['id'], st)
    _event(store, 'the agent of target %s now takes acme\'s command key %s… (by %s; the one before '
           'for %d h yet)' % (row['name'], cur['fp'][:16], by, OVERLAP_S // 3600), who=by,
           action='agent_cmdkey_moved', target=row['name'])
    return cur['fp']


def enc_new(store, row, by):
    """The agent's key for secrets made anew (op enckey): acme seals to the new one."""
    G = _G()
    got = G.call(store, row, 'enckey', {'overlap_s': OVERLAP_S}, timeout=60)
    pub = got.get('enc_pub')
    if not got.get('ok') or not isinstance(pub, str):
        said = _txt(got.get('said'), 300)
        if 'not an operation' in said:
            said = TOO_OLD
        raise PluginError(said or 'the agent made no new key', retry=False)
    try:
        if len(base64.b64decode(pub)) != 32:
            raise ValueError
    except ValueError:
        raise PluginError('the agent answered no key to seal to', retry=False)
    st = G.state(store, row['id'])
    st['enc_pub'] = pub
    st['enc_at'] = time.time()
    G.state_put(store, row['id'], st)
    _event(store, 'the agent of target %s made a new key for secrets (by %s)' % (row['name'], by),
           who=by, action='agent_enckey_new', target=row['name'])
    return pub


def rotate_now(store, row, what, by):
    """A full administrator's Rotate now: the command key (a new one for acme when this agent
    pins the current one already) and / or the agent's key for secrets."""
    if what not in ('command', 'seal', 'both'):
        raise ValueError('what: command, seal or both')
    G = _G()
    st = G.state(store, row['id'])
    if not st.get('cert_fp'):
        raise PluginError('the agent of %s has not joined' % row['name'], retry=False)
    out = {}
    if what in ('command', 'both'):
        if _too_old(st, 'cmdkey'):
            # hunt R f1: asked of an agent before 1.0.138, acme made itself a new command key
            # first (one an acme downgraded later signs with) and then failed
            raise PluginError(TOO_OLD, retry=False)
        if pinned_fp(store, st) == _cmd_current(store)[0]['fp']:
            age = time.time() - _cmd_current(store)[1]
            if age < 3600:
                raise PluginError('acme\'s command key was made less than an hour ago - this '
                                  'agent takes it already', retry=False)
            cmd_new(store, by)
        out['cmd_fp'] = cmd_move(store, row, by)
    if what in ('seal', 'both'):
        if _too_old(st, 'enckey'):
            raise PluginError(TOO_OLD, retry=False)
        enc_new(store, row, by)
        out['enc'] = True
    return out


TOO_OLD = 'the agent is too old to change keys (update it to 1.0.138 or later)'


def _too_old(st, feature):
    """The agent said what it can do (a hello since acme 1.0.138) and this is not of it."""
    return isinstance(st.get('features'), list) and not can(st, feature)


def retire(store):
    """Earlier command keys no agent pins any more (and past the overlap): their seed taken
    away - a backup made before the change still has it; the record of when stays."""
    G = _G()
    used = set()
    base = str(store.get_meta(M_CMDBASE) or '')
    for r in G.rows(store):
        st = G.state(store, r['id'])
        if not st.get('cert_fp') and not st.get('pending'):
            continue
        fp = str(st.get('cmd_fp') or '') or base
        used.add(fp)
        if st.get('cmd_prev_fp') and float(st.get('cmd_prev_until') or 0) > time.time():
            used.add(st['cmd_prev_fp'])
    cur = _cmd_current(store)[0]['fp']
    used.add(cur)
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:cmdkey:%'"):
        v = _jl(r['v'], {})
        fp = r['k'].rsplit(':', 1)[1]
        if not isinstance(v, dict) or not v.get('seed') or fp in used:
            continue
        if time.time() - float(v.get('replaced_at') or v.get('at') or 0) < OVERLAP_S + 86400:
            continue
        v['seed'] = None
        v['retired_at'] = time.time()
        _put(store, r['k'], v)
        _event(store, 'acme\'s command key %s… was retired: no agent takes it any more' % fp[:16],
               action='agent_cmdkey_retired')


def _age_days(at):
    return round((time.time() - float(at)) / 86400, 1) if at else None


def keys_of(store, row, st):
    """One agent's keys and their age (the card, the report)."""
    cur, cur_at = _cmd_current(store)
    fp = pinned_fp(store, st) if st.get('cert_fp') else ''
    key_at = cur_at if fp == cur['fp'] else float(_obj(store, M_CMDKEY % fp).get('at') or 0) \
        if fp else 0
    o = opts(store, row['id'])
    enc_at = float(st.get('enc_at') or st.get('joined_at') or 0)
    out = {'cmd_fp': fp, 'cmd_current': fp == cur['fp'] if fp else None,
           'cmd_at': key_at or None, 'cmd_age': _age_days(key_at),
           'enc_at': enc_at or None, 'enc_age': _age_days(enc_at),
           'tls_end': st.get('cert_end'), 'tls_renewed': st.get('renewed_at') or
           st.get('joined_at'), 'key_fp': st.get('key_fp') or '',
           'joined_at': st.get('joined_at'), 'rotate': o['rotate'],
           'rotate_days': o['rotate_days'], 'can': can(st, 'cmdkey') and can(st, 'enckey'),
           'said': st.get('key_said') or '',
           'prev_until': st.get('cmd_prev_until') if float(st.get('cmd_prev_until') or 0) >
           time.time() else None, 'unknown': unknown_cmd_key(store, st)}
    due = []
    if o['rotate'] and st.get('cert_fp'):
        lim = o['rotate_days'] * 86400
        if fp and fp != cur['fp']:
            due.append('command')
        elif key_at and time.time() - key_at > lim:
            due.append('command')
        if enc_at and time.time() - enc_at > lim:
            due.append('seal')
    out['due'] = due
    return out


def keys_report(store):
    """The age of every key: acme's authority, its own certificate, its command keys (with
    the agents that pin each), and each agent's."""
    G = _G()
    cur, cur_at = _cmd_current(store)
    ca = G.ca_public(store) or {}
    ctl = E._meta_obj(store, G.M_CTL)
    try:
        ctl_end = G.cert_end(ctl['cert']) if ctl.get('cert') else None
    except PluginError:
        ctl_end = None
    keys = {cur['fp']: {'fp': cur['fp'], 'at': cur_at or None, 'age': _age_days(cur_at),
                        'current': True, 'retired_at': None, 'agents': []}}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:cmdkey:%'"):
        v = _jl(r['v'], {})
        fp = r['k'].rsplit(':', 1)[1]
        if not isinstance(v, dict) or fp == cur['fp']:
            continue
        keys[fp] = {'fp': fp, 'at': v.get('at'), 'age': _age_days(v.get('at')),
                    'current': False, 'retired_at': v.get('retired_at'),
                    'replaced_at': v.get('replaced_at'), 'agents': []}
    agents = []
    for r in G.rows(store):
        st = G.state(store, r['id'])
        if not st.get('cert_fp'):
            continue
        k = keys_of(store, r, st)
        k.update(id=r['id'], name=r['name'],
                 platform=st.get('platform') or ('windows' if r.get('kind') == 'agent_windows'
                                                 else 'linux'))
        agents.append(k)
        if k['cmd_fp'] in keys:
            keys[k['cmd_fp']]['agents'].append(r['name'])
    return {'ca': {'fp': ca.get('fp'), 'at': ca.get('at'), 'age': _age_days(ca.get('at')),
                   'end': ca.get('end')},
            'ctl': {'end': ctl_end, 'at': ctl.get('at'), 'age': _age_days(ctl.get('at'))},
            'cmd': sorted(keys.values(), key=lambda x: (not x['current'],
                                                        -(float(x.get('at') or 0)))),
            'agents': agents, 'overlap_h': OVERLAP_S // 3600}


def rotate_all(store, by):
    """Settings → Target agents → Change acme's command key: a new one, every agent whose keys
    are changed on a schedule moved to it (the others keep theirs, still signed for)."""
    G = _G()
    fp = cmd_new(store, by)
    moved, left = [], []
    for r in G.rows(store):
        st = G.state(store, r['id'])
        if not st.get('cert_fp') or not opts(store, r['id'])['rotate']:
            continue
        try:
            cmd_move(store, r, by)
            moved.append(r['name'])
        except (PluginError, OSError, ValueError) as e:
            left.append({'name': r['name'], 'said': _txt(e, 300)})
    return {'fp': fp, 'moved': moved, 'left': left}


def _rotate_due(store, row, st):
    o = opts(store, row['id'])
    if not o['rotate'] or not st.get('cert_fp') or time.time() - float(
            st.get('last_seen') or 0) > _G().QUIET_S:
        return
    cur, cur_at = _cmd_current(store)
    lim = o['rotate_days'] * 86400
    # hunt R f1: an agent that cannot take a new command key made acme a new one all the same
    # every N days (never taken by it, signed with by an acme downgraded later)
    if not _too_old(st, 'cmdkey'):
        if cur_at and time.time() - cur_at > lim:
            cmd_new(store, 'the schedule')
        if pinned_fp(store, st) != _cmd_current(store)[0]['fp'] and not st.get('key_said'):
            cmd_move(store, row, 'the schedule')
    st = _G().state(store, row['id'])
    enc_at = float(st.get('enc_at') or st.get('joined_at') or 0)
    if enc_at and time.time() - enc_at > lim and can(st, 'enckey'):
        enc_new(store, row, 'the schedule')


# ---- B6: what the service serves ----------------------------------------------------------------
def served_on(store, row, st):
    """Is what the service serves asked of this agent? Only when switched on on its card (off
    by default) and only where its policy allows `probe local` already."""
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    return opts(store, row['id'])['health'] == 'on' and bool(pol.get('probe_local'))


def _deploys(store, row):
    return store.db.rows(
        'SELECT d.*, c.name AS cert_name, c.fingerprint AS cert_fp, c.version AS cert_version, '
        'c.names AS cert_names FROM cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE '
        'd.target = ? AND COALESCE(d.enabled, 1) <> 0 AND COALESCE(c.enabled, 1) <> 0 ORDER BY '
        'd.id', (row['name'],))


def served_check(store, row, force=False, by=''):
    """Each deployment of the target asked what its service serves (op probe at 127.0.0.1 on
    its port - what `allow probe local` allows): ok, old (deployed, but the service serves the
    certificate before - a reload forgotten), other, unreachable. -> {dep id: result}."""
    from acmelib.certs import checks, pki
    from acmelib.certs import store as S
    G = _G()
    st = G.state(store, row['id'])
    if not served_on(store, row, st):
        return {}
    key = M_SERVED % int(row['id'])
    have = _obj(store, key)
    now = time.time()
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    asked = 0
    keep = {}
    for d in _deploys(store, row):
        did = str(d['id'])
        was = have.get(did) if isinstance(have.get(did), dict) else {}
        if was:
            keep[did] = was
        if d.get('state') not in ('ok', 'deployed') or not d.get('deployed_fp'):
            continue
        last_ok = float(d.get('last_ok') or 0)
        due = force or not was or now - float(was.get('at') or 0) > HEALTH_EVERY_S or (
            last_ok > float(was.get('at') or 0) and now - last_ok > HEALTH_AFTER_S)
        if not due or asked >= HEALTH_MOST:
            continue
        places = checks.served_places(store, d) or []
        cert = S.cert_get(store, d['cert_id']) or {}
        names = [n for n in (S.jload(cert.get('names'), []) or []) if isinstance(n, str)]
        sni = next((n for n in names if not n.startswith('*.')), '')
        results = []
        for host, port, _want in places[:3]:
            if not host:
                continue                    # the certificate's name: not this server itself
            if host not in ('127.0.0.1', '::1', 'localhost') and \
                    G._txt('%s:%d' % (host, port), 300) not in (pol.get('probe') or []):
                continue                    # never a probe its policy does not allow already
            r = {'host': host, 'port': port}
            try:
                got = G.probe(store, row, host, port, sni=sni, timeout=10)
                leaf = pki.cert_info(got['chain'][0])
                fp = str(leaf.get('sha256') or '').upper()
                exp = checks.expected(store, cert)
                r.update(fp=fp, end=leaf.get('not_after'), names=[str(n) for n in (
                    leaf.get('names') or [])][:5], subject=_txt(leaf.get('subject_dn'), 200))
                if fp in exp['current']:
                    r['state'] = 'ok'
                elif fp in exp['old']:
                    r.update(state='old', version=exp['old'][fp])
                else:
                    r['state'] = 'other'
            except PluginError as e:
                r.update(state='unreachable', said=_txt(e, 300))
            except Exception as e:                      # noqa: BLE001
                r.update(state='unreachable', said=_txt(e, 300))
            results.append(r)
        asked += 1
        if not results:
            keep[did] = {'at': now, 'state': 'none', 'cert': d.get('cert_name'),
                         'said': 'no place of this deployment is on the server itself (a preset '
                                 'with a port) - nothing asked'}
            continue
        worst = next((s for s in ('old', 'other', 'unreachable', 'ok')
                      if any(x['state'] == s for x in results)), 'ok')
        res = {'at': now, 'state': worst, 'cert': d.get('cert_name'), 'places': results,
               'want': str(d.get('deployed_fp') or '').upper(),
               'version': d.get('deployed_version')}
        if worst == 'old' and was.get('state') != 'old':
            p = next(x for x in results if x['state'] == 'old')
            _event(store, '%s is deployed to %s, but the service still serves the old certificate '
                   '(version %s, at %s:%s) - reload it' % (
                       d.get('cert_name'), row['name'], p.get('version'), p['host'], p['port']),
                   'warn', action='agent_serves_old', target=row['name'],
                   cert=d.get('cert_name'))
        elif worst == 'ok' and was.get('state') in ('old', 'other'):
            _event(store, 'the service of %s on %s serves the deployed certificate now' % (
                d.get('cert_name'), row['name']), action='agent_serves_ok', target=row['name'],
                cert=d.get('cert_name'))
        keep[did] = res
    _put(store, key, keep)
    return keep


def served_view(store, row, st=None):
    st = st if st is not None else _G().state(store, row['id'])
    got = _obj(store, M_SERVED % int(row['id']))
    items = []
    for did, r in got.items():
        if isinstance(r, dict):
            items.append(dict(r, deploy_id=int(did) if did.isdigit() else did))
    items.sort(key=lambda x: str(x.get('cert') or ''))
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else {}
    return {'on': served_on(store, row, st), 'switch': opts(store, row['id'])['health'],
            'probe_local': bool(pol.get('probe_local')), 'items': items,
            'old': sum(1 for x in items if x.get('state') == 'old')}


def served_of_deploy(store, dep, kind=None):
    """What the deployment's service serves (B6) for the deployment's own view - or None."""
    try:
        trow = store.db.row('SELECT id, kind FROM cert_targets WHERE name = ?',
                            (dep.get('target'),))
        if not trow or trow.get('kind') not in _G().AGENT_KINDS:
            return None
        if opts(store, trow['id'])['health'] != 'on':
            return None                     # not asked for this agent (off by default)
        r = _obj(store, M_SERVED % int(trow['id'])).get(str(dep.get('id')))
        if not isinstance(r, dict) or r.get('state') in (None, 'none'):
            return None
        if str(r.get('want') or '') and str(dep.get('deployed_fp') or '').upper() != r['want']:
            return None                     # deployed again since: asked again soon
        return {k: r.get(k) for k in ('at', 'state', 'places', 'version', 'want')}
    except Exception:                                   # noqa: BLE001
        return None


# ---- the card, the tiles, the alerts, now and then -----------------------------------------------
def summary(store, row, st):
    """What info() carries (the tiles and the card's head): small, no secret."""
    o = opts(store, row['id'])
    out = {'audit': audit_view(store, row, st), 'opts': {k: o[k] for k in DEFAULTS}}
    if o['anomaly']:
        items = anomalies(store, row, st)
        out['anomalies'] = [{'kind': i['kind'], 'level': i['level'], 'words': i['words']}
                            for i in items][:12]
    else:
        out['anomalies'] = None
    sv = served_view(store, row, st)
    out['served'] = {'on': sv['on'], 'old': sv['old'],
                     'items': [{'cert': i.get('cert'), 'state': i.get('state'),
                                'deploy_id': i.get('deploy_id')} for i in sv['items']][:20]}
    if st.get('cert_fp'):
        k = keys_of(store, row, st)
        out['keys'] = {'due': k['due'], 'cmd_age': k['cmd_age'], 'enc_age': k['enc_age'],
                       'rotate': k['rotate'], 'unknown': bool(k['unknown'])}
    return out


def view(store, row):
    """The card's "Watching this agent" (GET /api/agents/guard)."""
    G = _G()
    st = G.state(store, row['id'])
    return {'id': row['id'], 'name': row['name'], 'opts': opts(store, row['id']),
            'joined': bool(st.get('cert_fp')), 'features': st.get('features'),
            'platform': st.get('platform') or ('windows' if row.get('kind') == 'agent_windows'
                                               else 'linux'),
            'audit': audit_view(store, row, st, full=True),
            'anomaly': anomaly_view(store, row, st), 'served': served_view(store, row, st),
            'keys': keys_of(store, row, st) if st.get('cert_fp') else None,
            'overlap_h': OVERLAP_S // 3600, 'rotate_range': list(ROTATE_DAYS)}


def alerts(store, row, st):
    out = []
    now = time.time()
    o = opts(store, row['id'])
    tid = row['id']
    if o['audit']:
        a = _obj(store, M_AUDIT % int(tid))
        if a.get('problems'):
            p = a['problems'][-1]
            out.append({'key': 'agent-audit:%s' % tid, 'level': 'bad',
                        'words': 'the audit chain of the agent of target %s does not agree with '
                                 'acme: %s' % (row['name'], p.get('words') or p.get('kind'))})
    if o['anomaly']:
        for i in anomalies(store, row, st, now):
            if i['kind'] == 'quiet' or (i['kind'] == 'clock' and i['level'] == 'bad'):
                continue                    # said by the alerts of every agent already
            out.append({'key': 'agent-anomaly:%s:%s' % (tid, i['kind']), 'level': i['level'],
                        'words': i['words']})
    elif unknown_cmd_key(store, st):
        out.append({'key': 'agent-anomaly:%s:cmdkey' % tid, 'level': 'bad',
                    'words': 'the agent of target %s pins a command key acme does not have (%s…) '
                             '- acme\'s jobs are refused once its overlap ends' % (
                                 row['name'], unknown_cmd_key(store, st)[:16])})
    for did, r in (_obj(store, M_SERVED % int(tid)) if o['health'] == 'on' else {}).items():
        if isinstance(r, dict) and r.get('state') == 'old':
            p = next((x for x in r.get('places') or [] if x.get('state') == 'old'), {})
            out.append({'key': 'agent-served:%s' % did, 'level': 'warn',
                        'words': '%s is deployed to %s, but the service still serves the old '
                                 'certificate (version %s, at %s:%s) - reload it' % (
                                     r.get('cert'), row['name'], p.get('version'),
                                     p.get('host'), p.get('port'))})
    return out


def tick(store, row, st):
    """On the node that leads, for each joined agent (agents.tick): the chain read when it grew,
    its anomalies looked at, its keys changed when due, what its services serve asked."""
    tid = int(row['id'])
    o = opts(store, tid)
    now = time.time()
    answering = now - float(st.get('last_seen') or 0) < _G().QUIET_S
    if o['anomaly']:
        evaluate(store, row, st)
    if o['audit'] and answering:
        a = _obj(store, M_AUDIT % tid)
        head = int((a.get('head') or {}).get('n') or 0)
        ver = int(a.get('verified_n') or 0)
        if now - float(a.get('rechecked_at') or a.get('base_at') or now) > 86400:
            _later('audit', tid, read_chain, store, row, 'the schedule', True)
        elif head > ver and (head - ver >= FETCH_LAG or now - float(a.get('verified_at') or 0) >
                             FETCH_EVERY_S):
            _later('audit', tid, read_chain, store, row)
    if o['rotate'] and answering:
        _later('rotate', tid, _rotate_due, store, row, st)
    if answering and served_on(store, row, st):
        _later('served', tid, served_check, store, row)


def sweep(store):
    """Now and then (the leader): the jobs kept for the chains, a month old, taken away; the
    command keys no agent pins retired."""
    cut = time.time() - SENT_KEEP_S
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agentsent:%'"):
        v = _jl(r['v'], {})
        if not isinstance(v, dict) or float(v.get('at') or 0) < cut:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
    try:
        if store.get_meta(M_CMDBASE):
            retire(store)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('agent-retire', 'retiring command keys: %s' % e, 'warn', every=3600)
