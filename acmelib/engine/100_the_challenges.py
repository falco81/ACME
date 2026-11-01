# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the challenges ------------------------------------------------------------------
def chal_key(state):
    return 'chal:' + hashlib.sha256(bytes(state)).hexdigest()[:40]


def chal_new(store, data):
    """A challenge kept; returns the State the VPN sends back."""
    state = CHAL_PREFIX + secrets.token_bytes(24)
    data = dict(data, exp=time.time() + int(CONFIG.get('code_ttl_s') or 300), tries=0,
                made=time.time(), node=node_name())
    store.set_meta(chal_key(state), json.dumps(data))
    return state


def chal_get(store, state):
    k = chal_key(state)
    raw = store.get_meta(k)
    if not raw:
        return None, None
    try:
        got = json.loads(raw)
    except ValueError:
        return None, None
    return got, raw


def chal_put(store, state, raw_was, data):
    """Written only if nobody wrote it meanwhile; whether it was."""
    return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                             (json.dumps(data), chal_key(state), raw_was)))


def chal_take(store, state, raw_was):
    """Used up: of two nodes taking the same answer at once, only one wins."""
    return bool(store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (chal_key(state), raw_was)))


def chal_drop(store, state):
    """Done with, whatever it holds now: after a code taken once - the token's
    step, a recovery code, once_take - another answer that only counted a try
    meanwhile no longer refuses the right one (1.0.139)."""
    store.db.run('DELETE FROM meta WHERE k = ?', (chal_key(state),))


def chal_tidy(store):
    """Challenges past their time, and the counts of sent codes."""
    t = time.time()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'chal:%' OR k LIKE 'codesent:%'"):
        try:
            v = json.loads(r['v'] or 'null')
        except ValueError:
            v = None
        if r['k'].startswith('chal:'):
            gone = not isinstance(v, dict) or float(v.get('exp') or 0) < t - 60
        else:
            span = 60 * int(CONFIG.get('code_send_window_min') or 15)
            gone = not isinstance(v, list) or not any(t - float(x) < span for x in v)
        if gone:
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))


