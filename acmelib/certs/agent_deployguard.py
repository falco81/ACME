# -*- coding: utf-8 -*-
"""
The agent checks WHAT it deploys (1.0.140, A1 - docs/target-agent.md "What the agent deploys").

Three optional lines of the agent's policy (root's, as every line - acme never changes it):

    allow issuer sha256=HEX         every certificate written chains to one of these CAs (the
                                    agent checks the signatures itself; the chain a job carries
                                    is only what the path is built from)
    allow names *.example.com ...   every name of every end certificate is one of these
    require key local               the key is one the agent made (keygen) - acme's is refused

The agent (deploy/agent/acme_agent.py guard_check) checks them before it writes anything; acme
checks a deployment against the policy the agent last said BEFORE it sends it (check(): the
same code - the agent's own guard_check, run here on the certificate acme would send) and says
why in What happens and in the deployment's error. Without the lines nothing of this runs.

What acme sends besides (only to an agent that says `deploy-guard` in its hello features - an
older agent never gets a key it does not know): args.guard = {chain: [PEM of the CAs the policy
allows that acme knows - the path's top when the chain leaves it out], pass_sealed: the
PKCS#12's password sealed to the agent (it opens acme's PKCS#12 to look into it)}.

    clean_policy_part(p)    the three as the agent reports them, shapes checked (agents.py)
    guard_of(pol)           {issuers, names, key_local} or None
    summary(pol)            the card's pill: {issuers, names, key_local, words}
    known_cas(store, row)   the CAs acme knows (its own authorities, the CAs in its
                            certificates' chains) - for the builder's "Allowed issuers"
    deployed_names(store, row)  the names of the certificates deployed to the target
    check(...)              a deployment against the guard -> problems
    before_send(...)        the hook of targets/agent.py deploy(): checked, args.guard added
    needs_items(...)        What happens / the deployment's needs card: one item per line
"""
from __future__ import annotations

import re
import shutil
import tempfile

HEX64 = re.compile(r'[0-9a-f]{64}\Z')
NAME_RE = re.compile(r'(\*\.)?[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\Z|'
                     r'[0-9a-f:.]{2,45}\Z')
FEATURE = 'deploy-guard'
CAS_MOST = 200
CERTS_SCAN = 5000


def _txt(v, most):
    return re.sub(r'[\x00-\x1f\x7f\x80-\x9f]', '', str(v if v is not None else ''))[:most]


def clean_policy_part(p):
    """allow issuer / allow names / require key local as the agent says them - each of its
    shape, cut to size; nothing when it says none (the policy as before)."""
    out = {}
    iss = p.get('issuers') if isinstance(p.get('issuers'), list) else []
    iss = [x.lower() for x in iss[:64] if isinstance(x, str) and HEX64.match(x.lower())]
    if iss:
        out['issuers'] = iss
    names = p.get('names') if isinstance(p.get('names'), list) else []
    names = [_txt(x, 253).lower() for x in names[:500] if isinstance(x, str) and
             NAME_RE.match(x.lower())]
    if names:
        out['names'] = names
    if p.get('key_local') is True:
        out['key_local'] = True
    return out


def guard_of(pol):
    if not isinstance(pol, dict):
        return None
    g = {'issuers': list(pol.get('issuers') or []), 'names': list(pol.get('names') or []),
         'key_local': bool(pol.get('key_local'))}
    return g if g['issuers'] or g['names'] or g['key_local'] else None


def words(g):
    bits = []
    if g.get('issuers'):
        n = len(g['issuers'])
        bits.append('%d issuer%s' % (n, '' if n == 1 else 's'))
    if g.get('names'):
        n = len(g['names'])
        bits.append('%d name%s' % (n, '' if n == 1 else 's'))
    if g.get('key_local'):
        bits.append('own key')
    return ', '.join(bits)


def summary(pol):
    """The agent card's pill ("Guards what it deploys: 2 issuers, 3 names, own key") - or None."""
    g = guard_of(pol)
    if not g:
        return None
    return {'issuers': len(g['issuers']), 'names': len(g['names']), 'key_local': g['key_local'],
            'words': words(g), 'issuer_fps': g['issuers'][:64], 'name_list': g['names'][:500]}


def loosened(was, pol):
    """What the policy may deploy now that it could not when `was` (a guard_of) was its usual:
    a CA or a name more, a line taken away - for the anomalies (A7: widened)."""
    if not isinstance(was, dict):
        return []
    now = guard_of(pol) or {'issuers': [], 'names': [], 'key_local': False}
    out = []
    if was.get('issuers'):
        if not now['issuers']:
            out.append('allow issuer taken away: a certificate of any CA')
        else:
            out += ['allow issuer sha256=%s… (a CA more)' % f[:16] for f in now['issuers']
                    if f not in was['issuers']]
    if was.get('names'):
        if not now['names']:
            out.append('allow names taken away: any name')
        else:
            out += ['allow names %s (a name more)' % n for n in now['names']
                    if n not in was['names']]
    if was.get('key_local') and not now['key_local']:
        out.append('require key local taken away: acme\'s key too')
    return out


def supported(st):
    return FEATURE in ((st or {}).get('features') or [])


# ---- what acme knows of CAs ----------------------------------------------------------------------
def _info(pem):
    from acmelib.certs import pki
    try:
        return pki.cert_info(pem)
    except Exception:                                   # noqa: BLE001
        return None


def _pems(text):
    from acmelib.certs import pki
    try:
        return [p for label, p in pki.split_pem(text or '') if label == 'CERTIFICATE']
    except Exception:                                   # noqa: BLE001
        return []


def known_cas(store, row=None):
    """[{fp, title, subject, root, kind: authority|chain, sources, certs, here, not_after}]: the
    CAs acme knows - its own authorities, and every CA in the chains of its certificates (by the
    source they came from) - the ones of the certificates deployed to `row` first (here)."""
    out = {}

    def add(pem, kind, source=None, cert=None, here=False):
        info = _info(pem)
        if not info or not info.get('is_ca'):
            return
        fp = str(info['sha256']).lower()
        one = out.get(fp)
        if one is None:
            if len(out) >= CAS_MOST:
                return
            one = out[fp] = {'fp': fp, 'title': info.get('cn') or info.get('subject_dn') or fp[:16],
                             'subject': info.get('subject_dn') or '', 'root': bool(
                                 info.get('self_signed')), 'kind': kind, 'sources': [],
                             'certs': 0, 'here': False, 'not_after': info.get('not_after'),
                             'pem': info.get('pem') or pem}
        if kind == 'authority':
            one['kind'] = 'authority'
        if source and source not in one['sources'] and len(one['sources']) < 8:
            one['sources'].append(source)
        if cert:
            one['certs'] += 1
        if here:
            one['here'] = True
    try:
        for r in store.db.rows('SELECT name, cert_pem, chain_pem FROM cert_cas ORDER BY name')[:100]:
            if r.get('cert_pem'):
                add(r['cert_pem'], 'authority', 'acme: %s' % r['name'])
            for p in _pems(r.get('chain_pem')):
                add(p, 'authority', 'acme: %s' % r['name'])
    except Exception:                                   # noqa: BLE001
        pass
    here = set()
    if row is not None:
        here = {int(d['cert_id']) for d in store.db.rows(
            'SELECT cert_id FROM cert_deploys WHERE target = ?', (row['name'],))
            if d.get('cert_id') is not None}
    for r in store.db.rows('SELECT id, issuer, chain_pem FROM certs WHERE chain_pem IS NOT NULL '
                           'ORDER BY id DESC')[:CERTS_SCAN]:
        for p in _pems(r.get('chain_pem')):
            add(p, 'chain', r.get('issuer') or '', cert=True, here=int(r['id']) in here)
    return sorted(out.values(), key=lambda c: (not c['here'], c['kind'] != 'authority',
                                               not c['root'], -c['certs'], c['title'].lower()))


def deployed_names(store, row):
    """The names of the certificates deployed to the target (the builder's "Allowed names")."""
    from acmelib.certs import store as S
    out = []
    for r in store.db.rows('SELECT c.names, c.name FROM cert_deploys d JOIN certs c ON '
                           'c.id = d.cert_id WHERE d.target = ? ORDER BY c.name',
                           (row['name'],))[:500]:
        got = S.jload(r.get('names'), None)
        names = got if isinstance(got, list) else [r.get('name')]
        for n in names:
            n = str(n or '').strip().lower().rstrip('.')
            if n and NAME_RE.match(n) and n not in out:
                out.append(n)
    return out[:500]


def builder_facts(store, row):
    """What the policy builder offers for the three lines: the CAs (no PEM), the names."""
    cas = []
    for c in known_cas(store, row):
        cas.append({k: c[k] for k in ('fp', 'title', 'subject', 'root', 'kind', 'sources',
                                      'certs', 'here', 'not_after')})
    from acmelib.certs import agent_keyplace
    try:
        keys = agent_keyplace.target_counts(store, row)
    except Exception:                                   # noqa: BLE001
        keys = None
    return {'cas': cas, 'names': deployed_names(store, row), 'keys': keys}


# ---- a deployment against the guard ---------------------------------------------------------------
def _bundle_pems(bundle):
    pems = []
    leaf = str(getattr(bundle, 'cert_pem', '') or '')
    if leaf:
        pems.append(leaf.strip() + '\n')
    for p in getattr(bundle, 'chain_pems', None) or []:
        p = p.decode('ascii', 'replace') if isinstance(p, bytes) else str(p or '')
        if p.strip():
            pems.append(p.strip() + '\n')
    return pems


def allowed_ca_pems(store, g):
    """The certificates of the CAs the policy allows that acme knows (the top of a path the
    chain leaves out)."""
    want = set(g.get('issuers') or [])
    if not want:
        return []
    return [c['pem'] for c in known_cas(store) if c['fp'] in want][:32]


def check(store, pol, bundle, agent_key, target=''):
    """The certificate acme would send against the guard of the policy the agent last said ->
    [problem words] (none: it allows it). The agent's own guard_check, run here on it - the
    key is judged by where it is made (acme's, or the agent's)."""
    g = guard_of(pol)
    if not g:
        return []
    out = []
    who = 'not sent: the policy of the agent on %s refuses it' % (target or 'the server')
    if g['key_local'] and not agent_key:
        out.append('%s (require key local): the key of this certificate is acme\'s - the agent '
                   'takes only a key it made itself: let the key be made on the server ("Key '
                   'made by the device")' % who)
    pems = _bundle_pems(bundle)
    if g['names'] and not pems and getattr(bundle, 'names', None):
        # not issued yet (What happens, a preview): the names it is asked for
        from acmelib.certs import agents as G
        m = G.agent_mod()
        bad = [n for n in bundle.names if not m.name_allowed(g['names'], n)]
        if bad:
            out.append('%s (allow names): the certificate %s holds the name %s - the policy '
                       'allows %s' % (who, getattr(bundle, 'name', '') or bad[0], bad[0],
                                      ', '.join(g['names'][:6]) + (' …' if len(g['names']) > 6
                                                                   else '')))
    if (g['issuers'] or g['names']) and pems:
        from acmelib.certs import agents as G
        m = G.agent_mod()
        sub = {'issuers': g['issuers'], 'names': g['names']}
        top = tempfile.mkdtemp(prefix='acme-guard-')
        try:
            m.guard_check(sub, [('the deployment', ''.join(pems).encode('ascii', 'replace'), '',
                                 None)], allowed_ca_pems(store, g) if store is not None else [],
                          own=[], top=top)
        except m.Refused as e:
            out.append(str(e).replace('refused by the policy of this machine', who, 1))
        except Exception as e:                          # noqa: BLE001
            out.append('%s: it could not be checked here (%s)' % (who, str(e)[:200]))
        finally:
            shutil.rmtree(top, ignore_errors=True)
    return out


def _state_of(ctx):
    try:
        from acmelib.certs import agents as G
        store = getattr(ctx, 'store', None)
        name = getattr(ctx, 'target_name', '') or ''
        if store is None or not name:
            return {}
        return G.state(store, G.target_row(store, name)['id'])
    except Exception:                                   # noqa: BLE001
        return {}


def before_send(target, bundle, options, r, args, agent_key):
    """targets/agent.py deploy(): the deployment checked against the guard of the agent's
    policy (as it last said it) before it is sent - PluginError with why; the agent checks it
    again itself. To an agent that knows the guard: what it builds the path from (args.guard)."""
    from acmelib.plugins.base import PluginError
    ctx = target.ctx
    info = ctx.agent_info() if hasattr(ctx, 'agent_info') else {}
    pol = (info or {}).get('policy')
    g = guard_of(pol)
    if not g:
        return
    store = getattr(ctx, 'store', None)
    name = getattr(ctx, 'target_name', '') or ''
    problems = check(store, pol, bundle, agent_key, name)
    if problems:
        for p in problems:
            ctx.step(p, 'bad')
        raise PluginError(problems[0], retry=False)
    ctx.step('the agent\'s policy checks what it deploys (%s): acme checked this certificate '
             'against it before sending - allowed; the agent checks it again itself' % words(g),
             'ok')
    st = _state_of(ctx)
    if not supported(st) and st:
        return
    gd = {'chain': allowed_ca_pems(store, g)} if store is not None else {'chain': []}
    pw = r.get('password') if isinstance(r, dict) else None
    from acmelib.plugins.targets._common import PFX_FORMATS
    if pw and not agent_key and any(f.get('format') in PFX_FORMATS for f in r.get('files') or []) \
            and hasattr(ctx, 'agent_seal'):
        # acme's PKCS#12: the agent opens it to look into it (its password sealed to it only)
        gd['pass_sealed'] = ctx.agent_seal('guard pfx', str(pw).encode('utf-8'))
    args['guard'] = gd


def needs_items(pol, bundle, agent_key, store=None, target=''):
    """The needs card / What happens: an item per line of the guard - allowed, or not with why
    (no line to add: what is refused is the certificate, not the policy)."""
    g = guard_of(pol)
    if not g:
        return []
    problems = check(store, pol, bundle, agent_key, target) if store is not None and \
        _bundle_pems(bundle) else []
    items = []

    def one(key, label, what):
        bad = [p for p in problems if '(%s)' % key in p]
        known = store is not None and bool(_bundle_pems(bundle)) or key == 'require key local'
        it = {'kind': 'guard', 'label': label, 'what': what, 'ok': (not bad) if known else None,
              'allow': ''}
        if bad:
            it['why'] = bad[0]
        items.append(it)
    if g['issuers']:
        one('allow issuer', 'the issuer', 'chains to one of %d CA%s the policy allows' % (
            len(g['issuers']), '' if len(g['issuers']) == 1 else 's'))
    if g['names']:
        one('allow names', 'the names', 'every name one of %s' % ', '.join(g['names'][:4]) + (
            ' …' if len(g['names']) > 4 else ''))
        if not _bundle_pems(bundle) and getattr(bundle, 'names', None):
            # not issued yet: the names it is asked for, judged as the agent judges them
            from acmelib.certs import agents as G
            m = G.agent_mod()
            out = [n for n in bundle.names if not m.name_allowed(g['names'], n)]
            items[-1]['ok'] = not out
            if out:
                items[-1]['why'] = 'the policy does not allow the name %s - the agent would ' \
                                   'refuse the certificate' % out[0]
    if g['key_local']:
        items.append({'kind': 'guard', 'label': 'the key', 'what': 'only a key made on the server',
                      'ok': bool(agent_key), 'allow': '',
                      **({} if agent_key else {'why': 'the key of this certificate is acme\'s - '
                                                      'let the key be made on the server ("Key '
                                                      'made by the device")'})})
    return items
