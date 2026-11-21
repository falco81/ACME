# -*- coding: utf-8 -*-
"""
The fleet of target agents (1.0.138, docs/agent-fleet.md): policy templates, groups of agents
with actions on all of them, the versions, update rings, and the certificates discovery found
that acme does not manage yet - with their take-over.

Everything here is kept in `meta` (so in every backup, on every node, put back by a restore as
the agents' own state and designs are):

    fleet:tpl:<id>          an administrator's own policy template: its versions (the last ten),
                            each with the policy text (read as the agent reads a policy file)
                            and the builder's state
    fleet:group:<id>        a group of agents: its name, colour, note, members (target ids), the
                            template its members should follow, whether it is the canary ring
    fleet:assign:<tid>      the template one agent should follow (before its groups')
    fleet:rollout           the update rollout under way (rings: the canary first, the rest after
                            a wait and when the canary is healthy)

The built-in templates ("nginx web", "Postfix + Dovecot", "IIS", "Remote Desktop" ...) are made
from the policy builder's own (agent_policy.templates) - the same folders, owners, modes, units
and tests - and are never saved.

What other modules call:

    agent_template(store, agent_id)   the template an agent should follow -> a dict (ref, title,
                                      platform, text, lines, via, group) or None. agent_id: the
                                      target's id, its name, or the agent's id (ag-...)
    drift(store, row, policy=None)    that template against the policy the agent last said ->
                                      {state: matches | differs | unknown, missing, extra} or
                                      None (no template)
    tick(store)                       the rollout's next step (the renewer, on the leader)

A template is documentation, as a design is: acme never sends a policy - root writes it on the
server. Nothing of this changes what any agent may do.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import shlex
import time

from acmelib.plugins.base import PluginError

TPL_PREFIX = 'fleet:tpl:'
GROUP_PREFIX = 'fleet:group:'
ASSIGN_PREFIX = 'fleet:assign:'
M_ROLLOUT = 'fleet:rollout'
TPL_KEPT = 10
TPL_MOST = 200
GROUPS_MOST = 200
NAME_MOST = 80
NOTE_MOST = 2000
TEXT_MOST = 32 * 1024
COLORS = ('blue', 'violet', 'teal', 'green', 'amber', 'orange', 'pink', 'slate')
ID_RE = re.compile(r'[a-z][0-9a-f]{10}\Z')
BUILTIN_PREFIX = 'builtin:'
WAIT_MIN = (0, 7 * 24 * 60)             # the rollout's wait after the canary (minutes)
CANARY_SHARE = 0.05                     # without a canary group: this share of the agents
ROLLOUT_KEEP_S = 30 * 86400             # a rollout that ended is shown this long
EXPIRY_SOON_S = 14 * 86400

# key, title, platform, the builder's templates it is made of (agent_policy), note
BUILTIN = [
    ('nginx-web', 'nginx web', 'linux', ('nginx',),
     'nginx with its certificates in /etc/nginx/ssl: nginx -t, a reload, a test of what it '
     'serves.'),
    ('apache-rhel', 'Apache (RHEL, Rocky, Alma)', 'linux', ('httpd',), ''),
    ('apache-debian', 'Apache (Debian, Ubuntu)', 'linux', ('apache2',), ''),
    ('haproxy', 'HAProxy', 'linux', ('haproxy',), ''),
    ('mail', 'Postfix + Dovecot', 'linux', ('postfix', 'dovecot'),
     'A mail server: Postfix and Dovecot with their folders, checks and reloads.'),
    ('exim', 'Exim', 'linux', ('exim',), ''),
    ('ldap', 'OpenLDAP', 'linux', ('openldap',), ''),
    ('postgresql', 'PostgreSQL', 'linux', ('postgresql',), ''),
    ('iis', 'IIS', 'windows', ('iis-all',),
     'Every IIS site: the machine store and the sites\' https bindings.'),
    ('rdp', 'Remote Desktop', 'windows', ('rdp',),
     'The Remote Desktop listener\'s certificate from the machine store.'),
    ('iis-rdp', 'IIS + Remote Desktop', 'windows', ('iis-all', 'rdp'), ''),
]


def _G():
    from acmelib.certs import agents
    return agents


def _P():
    from acmelib.certs import agent_policy
    return agent_policy


def _txt(v, most):
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]', '', str(v if v is not None else ''))[:most]


def _one_line(v, most):
    return _txt(re.sub(r'[\t\r\n  \x85]+', ' ', str(v if v is not None else '')),
                most).strip()


def _jload(text, default):
    try:
        got = json.loads(text) if text else default
    except (TypeError, ValueError):
        return default
    return got if isinstance(got, type(default)) else default


def _meta(store, k, default):
    return _jload(store.get_meta(k), default)


def _put(store, k, v):
    store.set_meta(k, json.dumps(v, sort_keys=True))


def _drop(store, k):
    store.db.run('DELETE FROM meta WHERE k = ?', (k,))


def _rows_like(store, prefix):
    return store.db.rows('SELECT k, v FROM meta WHERE k LIKE ? ORDER BY k', (prefix + '%',))


def _mod(platform):
    G = _G()
    return G.agent_mod_windows() if platform == 'windows' else G.agent_mod()


def _platform(v):
    return 'windows' if str(v or '') == 'windows' else 'linux'


# ---- templates ---------------------------------------------------------------------------------
def _state_of_parts(platform, parts):
    """The builder's state of some of its templates taken together (agent_policy.templates)."""
    P = _P()
    have = {t['key']: t for t in (P.templates_windows() if platform == 'windows'
                                  else P.templates())}
    st = {'files': [], 'units': [], 'tests': [], 'scripts': [], 'probe_local': False}
    if platform == 'windows':
        st.update(store=False, iis=[], rdp=False, roles=[])
    for key in parts:
        t = have.get(key)
        if not t:
            continue
        for f in t.get('files') or []:
            if platform == 'windows':
                same = [x for x in st['files'] if x['dir'].lower() == f['dir'].lower()]
                if same:
                    same[0]['readers'] = sorted(set(same[0]['readers']) | set(f['readers']))
                else:
                    st['files'].append({'dir': f['dir'], 'readers': list(f['readers'])})
                continue
            same = [x for x in st['files'] if x['dir'] == f['dir']]
            if same:
                same[0]['mode'] |= int(f['mode'])
            else:
                st['files'].append({'dir': f['dir'], 'owner': f['owner'], 'group': f['group'],
                                    'mode': int(f['mode'])})
        for u, verbs in sorted((t.get('units') or {}).items()):
            same = [x for x in st['units'] if x['name'] == u]
            if same:
                same[0]['verbs'] += [v for v in verbs if v not in same[0]['verbs']]
            else:
                st['units'].append({'name': u, 'verbs': list(verbs)})
        for a in t.get('tests') or []:
            if a not in st['tests']:
                st['tests'].append(list(a))
        st['probe_local'] = st['probe_local'] or bool(t.get('probe_local'))
        if platform == 'windows':
            st['store'] = st['store'] or bool(t.get('store'))
            st['rdp'] = st['rdp'] or bool(t.get('rdp'))
            for x in t.get('iis') or []:
                if x not in st['iis']:
                    st['iis'].append(x)
            for r, extra in sorted((t.get('roles') or {}).items()):
                for x in extra or ['']:
                    st['roles'].append({'role': r, 'extra': x})
    return st


def _q(word):
    return shlex.quote(str(word))


def _wq(word):
    return word if not re.search(r'[\s"\']', word) else '"%s"' % word


def lines_of_state(platform, st):
    """The policy lines of a builder's state, as `acme-agent policy show` writes them."""
    out = []
    win = platform == 'windows'
    for f in st.get('files') or []:
        if win:
            r = [x for x in f.get('readers') or [] if x]
            out.append('allow file %s%s' % (_wq(f['dir']), (' readers=%s' % _wq(','.join(r)))
                                            if r else ''))
        else:
            out.append('allow file %s owner=%s:%s mode=%04o' % (_q(f['dir']), f['owner'],
                                                                 f['group'], int(f['mode'])))
    for u in st.get('units') or []:
        out.append('allow %s %s %s' % ('service' if win else 'unit',
                                       _wq(u['name']) if win else _q(u['name']),
                                       ','.join(u['verbs'])))
    for a in st.get('tests') or []:
        out.append('allow test -- %s' % ' '.join(_q(x) for x in a))
    if win:
        if st.get('store'):
            out.append('allow store')
        for site in st.get('iis') or []:
            out.append('allow iis %s' % _wq(site))
        if st.get('rdp'):
            out.append('allow rdp')
        for r in st.get('roles') or []:
            out.append('allow role %s%s' % (r['role'], (' path=%s' % _wq(r['extra']))
                                            if r.get('extra') else ''))
    if st.get('probe_local'):
        out.append('allow probe local')
    return out


def state_of_policy(pol, platform):
    """The builder's state of a policy as the agent parsed it (policybuilder.js fromPolicy)."""
    win = platform == 'windows'
    st = {'files': [({'dir': f['dir'], 'readers': list(f.get('readers') or [])} if win else
                     {'dir': f['dir'], 'owner': f['owner'], 'group': f['group'],
                      'mode': int(f['mode'])}) for f in pol.get('files') or []],
          'units': [{'name': u, 'verbs': list(v)} for u, v in sorted(
              (pol.get('units') or {}).items())],
          'tests': [list(t) for t in pol.get('tests') or []],
          'scripts': [{'path': x['path'], 'sha256': x.get('sha256') or ''}
                      for x in pol.get('scripts') or []],
          'hashes': list(pol.get('script_hashes') or []), 'from': list(pol.get('from') or []),
          'probe': list(pol.get('probe') or []), 'connect': list(pol.get('connect') or []),
          'probe_local': bool(pol.get('probe_local')), 'self_update': bool(pol.get('self_update')),
          'connect_on': bool(pol.get('connect')), 'discover': list(pol.get('discover') or []),
          'limits': dict(pol.get('limits') or {})}
    if win:
        st.update(store=bool(pol.get('store')), iis=list(pol.get('iis') or []),
                  rdp=bool(pol.get('rdp')),
                  roles=[{'role': r, 'extra': x or ''} for r, xs in sorted(
                      (pol.get('roles') or {}).items()) for x in (xs or [''])],
                  key_read=list(pol.get('key_read') or []),
                  adcs=[dict(x) for x in pol.get('adcs') or []],
                  adcs_read=bool(pol.get('adcs_read')))
    return st


def _canon(platform, text):
    m = _mod(platform)
    return m.policy_lines(m.parse_policy(text or ''))


def _head(platform):
    m = _mod(platform)
    try:
        return m.policy_facts().get('head') or m.POLICY_HEAD
    except Exception:                                   # noqa: BLE001
        return getattr(m, 'POLICY_HEAD', '')


_BUILT = {}


def builtins():
    """The built-in templates, each with its state and its policy text (made once)."""
    if 'all' in _BUILT:
        return _BUILT['all']
    out = []
    for key, title, platform, parts, note in BUILTIN:
        st = _state_of_parts(platform, parts)
        lines = lines_of_state(platform, st)
        text = _head(platform) + '\n'.join(lines) + '\n'
        try:
            canon = _canon(platform, text)
        except Exception:                               # noqa: BLE001
            canon = lines
        out.append({'ref': BUILTIN_PREFIX + key, 'key': key, 'title': title, 'note': note,
                    'platform': platform, 'builtin': True, 'state': st, 'text': text,
                    'lines': canon, 'n': 1, 'at': None, 'by': 'acme'})
    _BUILT['all'] = out
    return out


def _own_all(store):
    out = []
    for r in _rows_like(store, TPL_PREFIX):
        d = _jload(r['v'], {})
        vs = d.get('versions') if isinstance(d.get('versions'), list) else []
        if not vs:
            continue
        cur = vs[-1]
        out.append({'ref': r['k'][len(TPL_PREFIX):], 'title': cur.get('title') or '',
                    'note': cur.get('note') or '', 'platform': _platform(cur.get('platform')),
                    'builtin': False, 'state': cur.get('state') or {},
                    'text': cur.get('text') or '', 'lines': cur.get('lines') or [],
                    'n': cur.get('n'), 'at': cur.get('at'), 'by': cur.get('by') or '',
                    'versions': len(vs)})
    out.sort(key=lambda t: t['title'].lower())
    return out


def templates(store, platform=None):
    """Every template - built-in ones first, then the administrators' own."""
    out = [dict(t) for t in builtins()] + _own_all(store)
    if platform:
        out = [t for t in out if t['platform'] == _platform(platform)]
    return out


def template_get(store, ref):
    ref = str(ref or '')
    if ref.startswith(BUILTIN_PREFIX):
        for t in builtins():
            if t['ref'] == ref:
                return dict(t)
        return None
    if not ID_RE.match(ref):
        return None
    for t in _own_all(store):
        if t['ref'] == ref:
            return t
    return None


def _new_id(prefix):
    return prefix + secrets.token_hex(5)


def template_save(store, b, by):
    """An administrator's own template (from the policy builder): its text read as the agent
    reads a policy file - a line it would not read is refused - and the builder's state."""
    P = _P()
    platform = _platform(b.get('platform'))
    title = _one_line(b.get('title'), NAME_MOST)
    if not title:
        raise ValueError('a template needs a title')
    text = b.get('text')
    if not isinstance(text, str) or not text.strip():
        raise ValueError('the template has no policy text')
    if len(text.encode('utf-8')) > TEXT_MOST or '\x00' in text:
        raise ValueError('a template is %d bytes at most, without NUL' % TEXT_MOST)
    m = _mod(platform)
    got = m.policy_check(text)
    if got['errors']:
        e = got['errors'][0]
        raise ValueError('line %d of the template: %s' % (e['line'], e['words']))
    st = P.clean_state(b.get('design_state') if b.get('design_state') is not None else {})
    if not st:
        # saved without the builder's state (the API, a script): the builder's state made from
        # the policy itself - the builder then adds exactly these lines
        st = P.clean_state(state_of_policy(got['pol'], platform))
    ref = str(b.get('ref') or '')
    if ref.startswith(BUILTIN_PREFIX):
        ref = ''                                        # a built-in one is never changed
    if ref:
        if not ID_RE.match(ref) or not store.get_meta(TPL_PREFIX + ref):
            raise LookupError('there is no such template')
    else:
        same = [t for t in _own_all(store) if t['title'].lower() == title.lower()
                and t['platform'] == platform]
        if same:
            ref = same[0]['ref']                        # the same title: a new version of it
        elif len(_own_all(store)) >= TPL_MOST:
            raise ValueError('%d templates at most' % TPL_MOST)
        else:
            ref = _new_id('t')
    d = _meta(store, TPL_PREFIX + ref, {})
    vs = d.get('versions') if isinstance(d.get('versions'), list) else []
    n = max([int(v.get('n') or 0) for v in vs] + [0]) + 1
    v = {'n': n, 'at': time.time(), 'by': _txt(by, 120), 'title': title,
         'note': _txt(b.get('note'), NOTE_MOST).strip(), 'platform': platform, 'text': text,
         'state': st, 'lines': m.policy_lines(got['pol']) if got.get('pol') else
         _canon(platform, text), 'hash': hashlib.sha256(text.encode('utf-8')).hexdigest()}
    _put(store, TPL_PREFIX + ref, {'versions': (vs + [v])[-TPL_KEPT:]})
    store.add_event('certificates', 'the fleet template %s was saved by %s (version %d, %d '
                    'line(s)) - documentation only: acme never sends a policy' % (
                        title, by, n, len(v['lines'])), who=by)
    return template_get(store, ref)


def template_delete(store, ref, by):
    ref = str(ref or '')
    if ref.startswith(BUILTIN_PREFIX):
        raise ValueError('a built-in template is not deleted')
    t = template_get(store, ref)
    if not t:
        raise LookupError('there is no such template')
    _drop(store, TPL_PREFIX + ref)
    # nobody follows it any more: its agents and groups have no template
    for r in _rows_like(store, ASSIGN_PREFIX):
        if _jload(r['v'], {}).get('ref') == ref:
            _drop(store, r['k'])
    for g in groups(store):
        if g.get('template') == ref:
            g['template'] = ''
            _put(store, GROUP_PREFIX + g['id'], g)
    store.add_event('certificates', 'the fleet template %s was deleted by %s' % (t['title'], by),
                    'warn', who=by)


# ---- groups ------------------------------------------------------------------------------------
def groups(store):
    out = []
    for r in _rows_like(store, GROUP_PREFIX):
        g = _jload(r['v'], {})
        if not g.get('id'):
            continue
        g['members'] = [int(x) for x in g.get('members') or [] if isinstance(x, int) or
                        str(x).isdigit()]
        out.append(g)
    out.sort(key=lambda g: (not g.get('canary'), str(g.get('name') or '').lower()))
    return out


def group_get(store, gid):
    gid = str(gid or '')
    if not ID_RE.match(gid):
        return None
    g = _meta(store, GROUP_PREFIX + gid, {})
    return g if g.get('id') else None


def _agent_ids(store):
    return {int(r['id']) for r in _G().rows(store)}


def _ids(v, what='ids'):
    if not isinstance(v, list):
        raise ValueError('%s is a list of target ids' % what)
    out = []
    for x in v[:5000]:
        if isinstance(x, bool):
            raise ValueError('%s is a list of target ids' % what)
        try:
            i = int(x)
        except (TypeError, ValueError):
            raise ValueError('%s is a list of target ids' % what)
        if i > 0 and i not in out:
            out.append(i)
    return out


def group_save(store, b, by):
    gid = str(b.get('id') or '')
    old = group_get(store, gid) if gid else None
    if gid and not old:
        raise LookupError('there is no such group')
    name = _one_line(b.get('name'), NAME_MOST) if 'name' in b or not old else old['name']
    if not name:
        raise ValueError('a group needs a name')
    others = [g for g in groups(store) if g['id'] != gid]
    if any(g['name'].lower() == name.lower() for g in others):
        raise ValueError('there is a group %s already' % name)
    if not old and len(others) >= GROUPS_MOST:
        raise ValueError('%d groups at most' % GROUPS_MOST)
    g = dict(old or {'id': _new_id('g'), 'members': [], 'template': '', 'canary': False,
                     'color': 'blue', 'note': ''})
    g['name'] = name
    if 'color' in b:
        g['color'] = b.get('color') if b.get('color') in COLORS else 'blue'
    if 'note' in b:
        g['note'] = _txt(b.get('note'), NOTE_MOST).strip()
    if 'members' in b:
        have = _agent_ids(store)
        mem = _ids(b.get('members'), 'members')
        bad = [x for x in mem if x not in have]
        if bad:
            raise ValueError('target %d is no target with acme-agent' % bad[0])
        g['members'] = mem
    if 'template' in b:
        ref = str(b.get('template') or '')
        if ref and not template_get(store, ref):
            raise ValueError('there is no such template')
        g['template'] = ref
    if 'canary' in b:
        g['canary'] = bool(b.get('canary'))
        if g['canary']:
            for o in others:                            # one canary ring
                if o.get('canary'):
                    o['canary'] = False
                    _put(store, GROUP_PREFIX + o['id'], o)
    g['at'], g['by'] = time.time(), _txt(by, 120)
    _put(store, GROUP_PREFIX + g['id'], g)
    store.add_event('certificates', 'the agents\' group %s was %s by %s (%d member(s))' % (
        name, 'changed' if old else 'made', by, len(g['members'])), who=by)
    return g


def group_delete(store, gid, by):
    g = group_get(store, gid)
    if not g:
        raise LookupError('there is no such group')
    _drop(store, GROUP_PREFIX + g['id'])
    store.add_event('certificates', 'the agents\' group %s was deleted by %s' % (g['name'], by),
                    'warn', who=by)


def group_members(store, gid, add=(), remove=(), by=''):
    g = group_get(store, gid)
    if not g:
        raise LookupError('there is no such group')
    mem = [x for x in g['members'] if x not in set(remove)]
    have = _agent_ids(store)
    for x in add:
        if x in have and x not in mem:
            mem.append(x)
    return group_save(store, {'id': g['id'], 'members': mem}, by)


# ---- which template an agent follows -------------------------------------------------------------
def _row_of(store, agent_id):
    """A target with acme-agent by its id, its name or its agent's id (ag-...)."""
    G = _G()
    ref = agent_id
    if isinstance(ref, str) and ref.startswith('ag-'):
        tid = store.get_meta(G.M_ID(ref))
        if not tid:
            return None
        ref = int(tid)
    elif isinstance(ref, str) and ref.isdigit():
        ref = int(ref)
    try:
        return G.target_row(store, ref)
    except (LookupError, ValueError, TypeError):
        return None


def assigned(store, tid):
    return _meta(store, ASSIGN_PREFIX + str(int(tid)), {}).get('ref') or ''


def agent_template(store, agent_id):
    """The template the agent should follow - its own assignment, else that of its first group
    (by name) that has one -> {ref, title, note, platform, builtin, text, lines, via: agent |
    group, group: name or ''} or None. For the alerts of drift (agentsec): compare `lines`
    with the policy the agent last said (drift() does)."""
    row = _row_of(store, agent_id)
    if not row:
        return None
    ref, via, gname = assigned(store, row['id']), 'agent', ''
    if not ref:
        for g in sorted(groups(store), key=lambda g: str(g.get('name') or '').lower()):
            if row['id'] in g['members'] and g.get('template'):
                ref, via, gname = g['template'], 'group', g['name']
                break
    if not ref:
        return None
    t = template_get(store, ref)
    if not t:
        return None
    return {'ref': t['ref'], 'title': t['title'], 'note': t.get('note') or '',
            'platform': t['platform'], 'builtin': t['builtin'], 'text': t['text'],
            'lines': list(t['lines']), 'n': t.get('n'), 'via': via, 'group': gname,
            'target': row['name'], 'target_id': row['id']}


def assign(store, ids, ref, by):
    """The template each of these agents follows (its own - before its groups'); '' none."""
    ref = str(ref or '')
    t = template_get(store, ref) if ref else None
    if ref and not t:
        raise ValueError('there is no such template')
    have = _agent_ids(store)
    done = []
    for tid in _ids(ids):
        if tid not in have:
            continue
        if ref:
            _put(store, ASSIGN_PREFIX + str(tid), {'ref': ref, 'at': time.time(),
                                                   'by': _txt(by, 120)})
        else:
            _drop(store, ASSIGN_PREFIX + str(tid))
        done.append(tid)
    if done:
        store.add_event('certificates', 'the fleet template of %d agent(s) was %s by %s' % (
            len(done), ('set to %s' % t['title']) if t else 'taken away', by), who=by)
    return done


def drift(store, row, policy=None, tpl=None):
    """The template the agent should follow against the policy it last said: {state: matches |
    differs | unknown, missing: lines of the template not on the server, extra: lines on the
    server not in the template, template: {ref, title, via, group}} - None with no template."""
    t = tpl if tpl is not None else agent_template(store, row['id'])
    if not t:
        return None
    if policy is None:
        st = _G().state(store, row['id'])
        policy = st.get('policy') if isinstance(st.get('policy'), dict) else None
    G = _G()
    plat = G.platform_of(store, row)
    head = {'ref': t['ref'], 'title': t['title'], 'via': t['via'], 'group': t['group'],
            'platform': t['platform']}
    if t['platform'] != plat:
        return {'state': 'other', 'missing': [], 'extra': [], 'template': head,
                'said': 'the template is for %s, the agent runs on %s' % (
                    'Windows' if t['platform'] == 'windows' else 'Linux',
                    'Windows' if plat == 'windows' else 'Linux')}
    c = _P().compare(t['text'], policy, _mod(plat))
    return {'state': c['state'], 'missing': c['added'], 'extra': c['removed'],
            'template': head}


# ---- the fleet as the pages show it -----------------------------------------------------------
def _vt(v):
    return tuple(int(x) for x in re.findall(r'\d+', str(v or ''))[:4])


def kind_of(a):
    os_ = str(a.get('os') or '').lower()
    if os_.startswith('kubernetes'):
        return 'kubernetes'
    return a.get('platform') or 'linux'


def health(a, d=None):
    """ok | warn | bad | idle, and why (in the pages' words)."""
    st = a.get('state')
    why = []
    if st in ('quiet', 'refused'):
        return 'bad', ['not heard from' if st == 'quiet' else 'refused']
    if st != 'answers':
        return 'idle', [{'new': 'not joined', 'joining': 'joining',
                         'off': 'switched off'}.get(st, st or 'not joined')]
    level = 'ok'
    if a.get('blocked'):
        level = 'warn'
        why.append('its policy blocks a deployment')
    end = a.get('cert_end')
    if end and float(end) - time.time() < EXPIRY_SOON_S:
        level = 'warn'
        why.append('its certificate ends soon')
    sysv = a.get('system') if isinstance(a.get('system'), dict) else {}
    if any((w or {}).get('level') == 'bad' for w in sysv.get('warnings') or []):
        level = 'warn'
        why.append('its server needs a look')
    if d and d.get('state') == 'differs':
        level = 'warn'
        why.append('drifted from its template')
    return level, why


def _agent_row(store, row, gmap, offered):
    G = _G()
    try:
        a = G.info(store, row)
    except Exception as e:                              # noqa: BLE001
        a = {'id': row['id'], 'name': row['name'], 'state': 'new', 'error': str(e)[:200]}
    t = None
    try:
        t = agent_template(store, row['id'])
    except Exception:                                   # noqa: BLE001
        t = None
    d = None
    if t:
        try:
            d = drift(store, row, a.get('policy'), t)
        except Exception:                               # noqa: BLE001
            d = {'state': 'unknown', 'missing': [], 'extra': []}
    lv, why = health(a, d)
    upd = a.get('update') or {}
    sysv = a.get('system') if isinstance(a.get('system'), dict) else {}
    facts = sysv.get('facts') if isinstance(sysv.get('facts'), dict) else {}
    return {'id': a['id'], 'name': a['name'], 'state': a.get('state'), 'mode': a.get('mode'),
            'platform': a.get('platform') or 'linux', 'kind': kind_of(a),
            'version': a.get('version') or '', 'host': a.get('host') or '',
            'os': a.get('os') or facts.get('os') or '', 'last_seen': a.get('last_seen'),
            'cert_end': a.get('cert_end'), 'joined': bool(a.get('joined')),
            'newer': bool(upd.get('newer')), 'self_update': bool(upd.get('allowed')),
            'offered': upd.get('offered') or offered, 'health': lv, 'why': why,
            'groups': gmap.get(a['id'], []),
            'template': {k: t[k] for k in ('ref', 'title', 'via', 'group', 'platform')}
            if t else None,
            'assigned': assigned(store, a['id']),
            'drift': {'state': d['state'], 'missing': len(d['missing']),
                      'extra': len(d['extra'])} if d else None,
            'policy': bool(a.get('policy'))}


def view(store):
    """The fleet: every agent (its health, version, groups, template and drift), the groups
    with their health, the templates, the versions, the rollout."""
    G = _G()
    gs = groups(store)
    gmap = {}
    for g in gs:
        for x in g['members']:
            gmap.setdefault(x, []).append(g['id'])
    try:
        pkg = G.package(build=False)
    except Exception:                                   # noqa: BLE001
        pkg = None
    import acmelib
    offered = (pkg or {}).get('version') or acmelib.__version__
    agents = [_agent_row(store, r, gmap, offered) for r in G.rows(store)]
    by_id = {a['id']: a for a in agents}
    count = {'ok': 0, 'warn': 0, 'bad': 0, 'idle': 0}
    for a in agents:
        count[a['health']] = count.get(a['health'], 0) + 1
    vers = {}
    for a in agents:
        if a['joined'] and a['version']:
            vers[a['version']] = vers.get(a['version'], 0) + 1
    versions = [{'version': v, 'count': n, 'current': _vt(v) >= _vt(offered)}
                for v, n in sorted(vers.items(), key=lambda x: _vt(x[0]), reverse=True)]
    tpls = templates(store)
    used = {}
    for a in agents:
        if a['template']:
            used[a['template']['ref']] = used.get(a['template']['ref'], 0) + 1
    out_groups = []
    for g in gs:
        mem = [by_id[x] for x in g['members'] if x in by_id]
        hc = {'ok': 0, 'warn': 0, 'bad': 0, 'idle': 0}
        for a in mem:
            hc[a['health']] += 1
        t = template_get(store, g['template']) if g.get('template') else None
        gv = {}
        for a in mem:
            if a['version']:
                gv[a['version']] = gv.get(a['version'], 0) + 1
        out_groups.append(dict(g, members=[a['id'] for a in mem], health=hc,
                               template_title=t['title'] if t else '',
                               drifted=len([a for a in mem if (a['drift'] or {}).get('state') ==
                                            'differs']),
                               versions=[{'version': v, 'count': n} for v, n in sorted(
                                   gv.items(), key=lambda x: _vt(x[0]), reverse=True)],
                               newer=len([a for a in mem if a['newer']])))
    return {'agents': agents, 'groups': out_groups, 'health': count, 'versions': versions,
            'offered': offered, 'signed': bool((pkg or {}).get('signed')),
            'templates': [dict({k: t.get(k) for k in ('ref', 'title', 'note', 'platform',
                                                      'builtin', 'lines', 'n', 'at', 'by',
                                                      'versions')}, used=used.get(t['ref'], 0))
                          for t in tpls],
            'rollout': rollout_view(store), 'colors': list(COLORS),
            'unmanaged': unmanaged_count(store)}


# ---- actions on many agents ----------------------------------------------------------------------
ACTIONS = ('ask', 'update')


def _rows_for(store, ids):
    G = _G()
    have = {int(r['id']): r for r in G.rows(store)}
    return [have[i] for i in _ids(ids) if i in have]


def act(store, action, ids, by):
    """Ask now / update, for each agent of the list - a job of its own (its steps say each)."""
    from acmelib.certs import jobs
    if action not in ACTIONS:
        raise ValueError('the action is one of %s' % ', '.join(ACTIONS))
    rows = _rows_for(store, ids)
    if not rows:
        raise ValueError('no agent was chosen')
    G = _G()

    def ask_all(job):
        ok = bad = 0
        for row in rows:
            try:
                a = G.look(store, row, by)
            except Exception as e:                      # noqa: BLE001
                a = {'state': 'quiet', 'said': str(e)[:300]}
            if a.get('state') == 'answers' and not a.get('said'):
                ok += 1
                job.step('%s: answers (acme-agent %s)' % (row['name'], a.get('version') or '?'),
                         'ok')
            else:
                bad += 1
                job.step('%s: %s' % (row['name'], a.get('said') or a.get('state') or '?'), 'warn')
        return (bad == 0), '%d of %d agent(s) answered' % (ok, len(rows))

    def update_all(job):
        cand = {c['id']: c for c in G.update_candidates(store)}
        done = skipped = failed = 0
        for row in rows:
            c = cand.get(row['id'])
            if not c:
                skipped += 1
                job.step('%s: runs the newest agent already (or has not joined)' % row['name'])
                continue
            if not c['ok']:
                skipped += 1
                job.step('%s: not updated - %s' % (row['name'], c['why']), 'warn')
                continue
            try:
                G.update_agent(store, row, by)
                done += 1
                job.step('%s: updated to %s' % (row['name'], c['offered']), 'ok')
            except PluginError as e:
                failed += 1
                job.step('%s: %s' % (row['name'], e), 'bad')
        return failed == 0, '%d updated, %d not, %d failed' % (done, skipped, failed)
    fn = ask_all if action == 'ask' else update_all
    said = ('ask %d agent(s) now' if action == 'ask' else 'update %d agent(s)') % len(rows)
    jid = jobs.submit(store, 'action', fn, by=by, said='the fleet: %s' % said)
    return {'job_id': jid, 'count': len(rows)}


def drift_many(store, ids):
    out = []
    for row in _rows_for(store, ids):
        t = agent_template(store, row['id'])
        d = drift(store, row, tpl=t) if t else None
        out.append({'id': row['id'], 'name': row['name'], 'drift': d})
    return out


# ---- update rings ------------------------------------------------------------------------------
def rollout_view(store):
    r = _meta(store, M_ROLLOUT, {})
    if not r.get('phase'):
        return None
    if r['phase'] in ('done', 'stopped') and time.time() - float(r.get('ended') or 0) > \
            ROLLOUT_KEEP_S:
        return None
    return r


def _cand(store):
    return {c['id']: c for c in _G().update_candidates(store)}


def rollout_plan(store, canary=''):
    """Who the canary ring is and who the rest - of the agents a newer one is offered to and
    acme can update now; the others with why not."""
    cand = _cand(store)
    ok = [c for c in cand.values() if c['ok']]
    skipped = [{'id': c['id'], 'name': c['name'], 'why': c['why']} for c in cand.values()
               if not c['ok']]
    if canary:
        g = group_get(store, canary)
        if not g:
            raise LookupError('there is no such group')
        ring = [c for c in ok if c['id'] in g['members']]
        how = 'group'
    else:
        n = max(1, int(math.ceil(len(ok) * CANARY_SHARE))) if ok else 0
        ring = sorted(ok, key=lambda c: c['name'].lower())[:n]
        how = 'share'
    ids = {c['id'] for c in ring}
    rest = [c for c in ok if c['id'] not in ids]
    sm = lambda c: {'id': c['id'], 'name': c['name'], 'version': c['version'],  # noqa: E731
                    'offered': c['offered']}
    return {'canary': sorted([sm(c) for c in ring], key=lambda x: x['name'].lower()),
            'rest': sorted([sm(c) for c in rest], key=lambda x: x['name'].lower()),
            'skipped': sorted(skipped, key=lambda x: x['name'].lower()), 'how': how}


def _run_ring(store, which, by):
    """The update of one ring, as a job."""
    from acmelib.certs import jobs
    G = _G()

    def fn(job):
        r = _meta(store, M_ROLLOUT, {})
        ring = r.get(which) or []
        res = r.setdefault('results', {})
        bad = 0
        for x in ring:
            cur = _meta(store, M_ROLLOUT, {})
            if cur.get('id') != r.get('id') or cur.get('phase') == 'stopped':
                job.step('the rollout was stopped', 'warn')
                return False, 'stopped'
            try:
                row = G.target_row(store, x['id'])
                G.update_agent(store, row, by)
                res[str(x['id'])] = {'ok': True, 'at': time.time()}
                job.step('%s: updated to %s' % (x['name'], r.get('version')), 'ok')
            except Exception as e:                      # noqa: BLE001
                bad += 1
                res[str(x['id'])] = {'ok': False, 'at': time.time(), 'said': str(e)[:300]}
                job.step('%s: %s' % (x['name'], e), 'bad')
        cur = _meta(store, M_ROLLOUT, {})
        if cur.get('id') == r.get('id') and cur.get('phase') != 'stopped':
            cur.setdefault('results', {}).update(res)
            if which == 'canary':
                cur['phase'] = 'waiting'
                cur['next_at'] = time.time() + 60 * int(cur.get('wait') or 0)
            else:
                cur['phase'] = 'done'
                cur['ended'] = time.time()
                store.add_event('certificates', 'the agents\' update rollout to %s is done: %d '
                                'agent(s), %d failed' % (cur.get('version'), len(
                                    cur.get('canary') or []) + len(cur.get('rest') or []),
                                    len([v for v in cur['results'].values() if not v['ok']])),
                                who=by)
            _put(store, M_ROLLOUT, cur)
        return bad == 0, '%d of %d updated' % (len(ring) - bad, len(ring))
    jid = jobs.submit(store, 'action', fn, by=by, said='the fleet\'s update rollout: the %s' % (
        'canary ring' if which == 'canary' else 'rest of the agents'))
    r = _meta(store, M_ROLLOUT, {})
    r['job_' + which] = jid
    _put(store, M_ROLLOUT, r)
    return jid


def rollout_start(store, b, by):
    """An update in rings: the canary ring (a group, or 5 % of the agents) at once; the rest
    once the wait is over and - unless told otherwise - every canary agent answers with the
    new version."""
    cur = rollout_view(store)
    if cur and cur['phase'] in ('canary', 'waiting', 'rest', 'held'):
        raise ValueError('a rollout is under way - stop it first')
    try:
        wait = int(b.get('wait') if b.get('wait') not in (None, '') else 60)
    except (TypeError, ValueError):
        raise ValueError('wait is a number of minutes')
    if not WAIT_MIN[0] <= wait <= WAIT_MIN[1]:
        raise ValueError('wait is %d to %d minutes' % WAIT_MIN)
    plan = rollout_plan(store, str(b.get('canary') or ''))
    if not plan['canary'] and not plan['rest']:
        raise ValueError('no agent can be updated now (%s)' % (
            plan['skipped'][0]['why'] if plan['skipped'] else 'every one runs the newest'))
    if b.get('canary') and not plan['canary']:
        # hunt R f1: a canary group none of whose agents can be updated now updated every
        # other agent at once - the rollout without its canary
        raise ValueError('no agent of the canary group can be updated now - the rest is not '
                         'updated without its canary ring (choose another group, or none)')
    import acmelib
    try:
        pkg = _G().package(build=False)
    except Exception:                                   # noqa: BLE001
        pkg = None
    r = {'id': secrets.token_hex(6), 'at': time.time(), 'by': _txt(by, 120),
         'version': (pkg or {}).get('version') or acmelib.__version__,
         'canary_group': str(b.get('canary') or ''), 'how': plan['how'], 'wait': wait,
         'healthy': b.get('healthy') is not False, 'canary': plan['canary'],
         'rest': plan['rest'], 'skipped': plan['skipped'], 'results': {},
         'phase': 'canary' if plan['canary'] else 'rest', 'next_at': None, 'held': ''}
    _put(store, M_ROLLOUT, r)
    store.add_event('certificates', 'an update rollout of the agents to %s was started by %s: '
                    '%d in the canary ring, %d after %d minute(s)' % (
                        r['version'], by, len(r['canary']), len(r['rest']), wait), who=by)
    _run_ring(store, 'canary' if plan['canary'] else 'rest', by)
    return rollout_view(store)


def canary_health(store, r):
    """Whether every canary agent runs the new version and answers - and who does not."""
    G = _G()
    now = time.time()
    bad = []
    for x in r.get('canary') or []:
        res = (r.get('results') or {}).get(str(x['id'])) or {}
        st = G.state(store, x['id'])
        if not res.get('ok'):
            bad.append('%s: not updated%s' % (x['name'], (' - ' + res['said']) if
                                              res.get('said') else ''))
        elif _vt(st.get('version')) < _vt(r.get('version')):
            bad.append('%s: still runs %s' % (x['name'], st.get('version') or '?'))
        elif now - float(st.get('last_seen') or 0) > G.QUIET_S or st.get('refused'):
            bad.append('%s: does not answer' % x['name'])
    return bad


def tick(store):
    """The rollout's next step (on the leader, with the agents' own tick)."""
    r = _meta(store, M_ROLLOUT, {})
    if r.get('phase') != 'waiting':
        return
    if time.time() < float(r.get('next_at') or 0):
        return
    bad = canary_health(store, r) if r.get('healthy') else []
    if bad:
        r['phase'] = 'held'
        r['held'] = '; '.join(bad)[:1000]
        _put(store, M_ROLLOUT, r)
        store.add_event('certificates', 'the agents\' update rollout to %s is held: the canary '
                        'ring is not healthy (%s)' % (r.get('version'), r['held']), 'warn')
        return
    r['phase'] = 'rest'
    _put(store, M_ROLLOUT, r)
    if r.get('rest'):
        _run_ring(store, 'rest', r.get('by') or 'acme')
    else:
        r['phase'], r['ended'] = 'done', time.time()
        _put(store, M_ROLLOUT, r)


def rollout_step(store, do, by):
    r = _meta(store, M_ROLLOUT, {})
    if not r.get('phase'):
        raise LookupError('there is no rollout')
    if do == 'stop':
        if r['phase'] in ('done', 'stopped'):
            raise ValueError('the rollout has ended')
        r['phase'], r['ended'] = 'stopped', time.time()
        _put(store, M_ROLLOUT, r)
        store.add_event('certificates', 'the agents\' update rollout to %s was stopped by %s' % (
            r.get('version'), by), 'warn', who=by)
    elif do == 'continue':
        if r['phase'] not in ('waiting', 'held'):
            raise ValueError('the rollout is not waiting')
        r['phase'], r['held'] = 'rest', ''
        _put(store, M_ROLLOUT, r)
        store.add_event('certificates', 'the agents\' update rollout to %s goes on with the rest, '
                        'by %s' % (r.get('version'), by), who=by)
        if r.get('rest'):
            _run_ring(store, 'rest', by)
        else:
            r['phase'], r['ended'] = 'done', time.time()
            _put(store, M_ROLLOUT, r)
    elif do == 'forget':
        if r['phase'] not in ('done', 'stopped'):
            raise ValueError('stop the rollout first')
        _drop(store, M_ROLLOUT)
        return None
    else:
        raise ValueError('do is stop, continue or forget')
    return rollout_view(store)


# ---- certificates nobody manages (discovery) -----------------------------------------------------
def _risk(days, cert):
    if days is None:
        return 'unknown', 0
    if days < 0:
        return 'expired', 100
    if days < 7:
        return 'critical', 90
    if days < 30:
        return 'high', 70
    if days < 60:
        return 'medium', 40
    sub, iss = str(cert.get('subject') or ''), str(cert.get('issuer') or '')
    if sub and sub == iss:
        return 'self-signed', 30
    return 'low', 10


def unmanaged(store):
    """Every certificate a kept discovery found on a server with acme-agent that acme does not
    manage - each with where it is served, when it ends, its risk; sorted by risk."""
    from acmelib.certs import agent_discover as AD
    G = _G()
    out = []
    for row in G.rows(store):
        try:
            v = AD.cached(store, row)
        except Exception:                               # noqa: BLE001
            v = None
        if not v or v.get('refused'):
            continue
        served = set()
        for f in v.get('found') or []:
            c = f.get('cert') or {}
            if not c or c.get('managed') or c.get('acme'):
                continue
            served.add(c.get('thumbprint'))
            out.append(_entry(row, v, f, c))
        for c in v.get('certs') or []:
            if c.get('managed') or c.get('acme') or c.get('thumbprint') in served:
                continue
            out.append(_entry(row, v, None, c))
    out.sort(key=lambda e: (-e['risk_n'], e['days'] if e['days'] is not None else 1e9,
                            e['target'].lower()))
    return out


def unmanaged_count(store):
    try:
        return len(unmanaged(store))
    except Exception:                                   # noqa: BLE001
        return 0


def _entry(row, v, f, c):
    days = c.get('days')
    risk, n = _risk(days, c)
    names = []
    for x in ([c.get('cn')] if c.get('cn') else []) + list(c.get('sans') or []) + \
            list((f or {}).get('names') or []):
        x = str(x or '').strip().lower().rstrip('.')
        if x and x not in names and re.fullmatch(r'(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)*', x):
            names.append(x)
    can = bool(f and (f.get('prefill') or {}) and f.get('items') is not None)
    return {'target': row['name'], 'target_id': row['id'], 'platform': v.get('platform'),
            'service': f['id'] if f else '', 'kind': (f or {}).get('kind') or '',
            'kind_title': (f or {}).get('kind_title') or '',
            'where': (f or {}).get('site') or (f or {}).get('config') or
            ', '.join((c.get('where') or [])[:2]),
            'names': names[:40], 'cn': c.get('cn') or '', 'issuer': c.get('issuer') or '',
            'subject': c.get('subject') or '', 'not_after': c.get('not_after'), 'days': days,
            'thumbprint': c.get('thumbprint') or '', 'risk': risk, 'risk_n': n,
            'found_at': v.get('at'), 'can_take': can and bool(names),
            'watch': (f or {}).get('watch') or c.get('watch')}


def _finding(store, target, service):
    from acmelib.certs import agent_discover as AD
    G = _G()
    ref = target
    try:
        ref = int(ref)
    except (TypeError, ValueError):
        pass
    row = G.target_row(store, ref)
    v = AD.cached(store, row)
    if not v or v.get('refused'):
        raise ValueError('nothing was discovered on %s yet - run a discovery first' % row['name'])
    f = [x for x in v.get('found') or [] if x.get('id') == str(service or '')]
    if not f:
        raise LookupError('that service is not among what was found on %s' % row['name'])
    return row, v, f[0]


def _item_allowed(m, pol, it, platform):
    """Whether the agent's policy (as it last said it) allows one item a deployment needs."""
    if not isinstance(pol, dict):
        return None
    k = it.get('kind')
    if k == 'file':
        rule = m.file_rule(pol, it['path'])
        if not rule:
            return False
        if (it.get('owner'), it.get('group')) != (rule['owner'], rule['group']):
            return False
        return not (int(it.get('mode') or 0) & ~int(rule['mode']))
    if k == 'unit':
        return it.get('verb') in ((pol.get('units') or {}).get(it.get('unit')) or [])
    if k == 'test':
        return list(it.get('argv') or []) in [list(x) for x in pol.get('tests') or []]
    if k == 'store':
        return bool(pol.get('store'))
    if k == 'rdp':
        return bool(pol.get('rdp'))
    if k == 'iis':
        have = [str(x).lower() for x in pol.get('iis') or []]
        return '*' in have or str(it.get('site') or '').lower() in have
    if k == 'role':
        return it.get('role') in (pol.get('roles') or {})
    return None


def _full_policy(m, pol):
    p = m.parse_policy('')
    for k, v in (pol or {}).items():
        if k in p or k in ('store', 'iis', 'rdp', 'roles', 'discover'):
            p[k] = v
    return p


def takeover_preview(store, b):
    """What taking over a certificate found on a server makes, before anything is made: the
    certificate in acme (the same names), the deployment to the same place through the agent,
    the policy lines that deployment needs (which the policy allows already), and what happens
    - nothing is written on the server until it is confirmed and the policy allows it."""
    from acmelib.certs import store as S
    from acmelib.certs import defaults as DF
    G = _G()
    row, v, f = _finding(store, b.get('target'), b.get('service'))
    c = f.get('cert') or {}
    if c.get('managed') or c.get('acme'):
        raise ValueError('acme manages that certificate already (%s)' % (
            (c.get('managed') or {}).get('name') or 'acme'))
    platform = v.get('platform') or G.platform_of(store, row)
    e = _entry(row, v, f, c)
    names = [str(x).strip().lower() for x in (b.get('names') or e['names'])
             if str(x).strip()][:100]
    if not names:
        raise ValueError('the certificate found names nothing acme could ask for')
    opts = dict(f.get('prefill') or {})
    if not opts:
        raise ValueError('acme cannot make a deployment of that service by itself - make it by '
                         'hand (Make a deployment)')
    st = G.state(store, row['id'])
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    m = _mod(platform)
    fpol = _full_policy(m, pol) if pol else None
    items, dirs = [], {}
    for it in f.get('items') or []:
        if it.get('kind') == 'file':
            # one line a folder: its files' modes taken together (a key 0600, a certificate 0644)
            d = it['path'].rsplit('/', 1)[0] or '/'
            if d in dirs:
                one = dirs[d]
                one['mode'] |= int(it.get('mode') or 0)
                one['ok'] = one['ok'] and (_item_allowed(m, fpol, it, platform) if fpol else None)
                one['allow'] = 'acme-agent allow file %s --owner %s:%s --mode %04o' % (
                    shlex.quote(d), one['owner'], one['group'], one['mode'])
                continue
            one = dict(it, ok=_item_allowed(m, fpol, it, platform) if fpol else None)
            dirs[d] = one
            items.append(one)
            continue
        ok = _item_allowed(m, fpol, it, platform) if fpol else None
        items.append(dict(it, ok=ok))
    allowed = bool(items) and all(x['ok'] for x in items) if fpol else False
    missing = [x['allow'] for x in items if not x['ok']]
    win = platform == 'windows'
    block = '\n'.join(('' if win else 'sudo ') + x for x in missing)
    name = _one_line(b.get('name'), 190) or S.safe_name(
        re.sub(r'^\*\.', 'wildcard.', names[0]),
        {r['name'] for r in store.db.rows('SELECT name FROM certs')})
    iss = str(b.get('issuer') or '').strip()
    if not iss:
        di = DF.default_issuer(store)
        iss = di['name'] if di else ''
    if iss and not S.plugin_row(store, 'issuer', iss):
        raise ValueError('there is no source %s' % iss)
    sources = [r['name'] for r in store.db.rows('SELECT name FROM cert_issuers ORDER BY name')]
    where = e['where'] or e['kind_title']
    steps = [
        ['cert', 'acme makes the certificate %s for %s from %s (nothing is issued yet)' % (
            name, ', '.join(names[:6]) + (' …' if len(names) > 6 else ''), iss or '?')],
        ['deploy', 'a deployment of it to %s through its acme-agent: %s' % (row['name'], where)]]
    for o in opts.get('outputs') or []:
        steps.append(['file', o])
    for k in ('test_cmd', 'reload_cmd'):
        for x in opts.get(k) or []:
            steps.append(['cmd', x])
    if allowed:
        steps.append(['ok', 'the agent\'s policy allows all of it: the certificate goes there '
                            'when it is issued (Issue and deploy now, or the next renewal)'])
    else:
        steps.append(['wait', 'the agent\'s policy does not allow all of it yet: until root adds '
                              'the lines below on the server, the agent refuses the deployment '
                              'whole - nothing is written there'])
    return {'target': row['name'], 'target_id': row['id'], 'platform': platform,
            'service': f['id'], 'kind_title': f.get('kind_title') or '', 'where': where,
            'found': e, 'cert': {'name': name, 'names': names, 'issuer': iss,
                                 'key_type': 'rsa-2048' if win else 'ec-256'},
            'deploy': {'target': row['name'], 'options': opts}, 'items': items,
            'allowed': allowed, 'policy_known': bool(pol), 'missing': missing,
            'block': block, 'steps': steps, 'sources': sources}


def takeover(store, b, by, full=False, s=None):
    """Taken over: the certificate made in acme, its deployment to the same place - and, only
    when asked and the agent's policy allows all of it, issued and deployed now."""
    from acmelib.certs import api as A
    p = takeover_preview(store, b)
    if not b.get('confirm'):
        raise ValueError('confirm it first (the preview says what is made)')
    if not p['cert']['issuer']:
        raise ValueError('choose the source the certificate is issued from')
    now = bool(b.get('issue_now'))
    if now and not p['allowed']:
        raise ValueError('the agent\'s policy does not allow the deployment yet - add the lines '
                         'on the server first, then ask the agent again')
    body = {'name': p['cert']['name'], 'names': p['cert']['names'],
            'issuer': p['cert']['issuer'], 'auto_renew': 1 if b.get('auto_renew', True) else 0,
            'note': 'taken over from %s (%s), found by discovery' % (p['target'], p['where'])}
    if b.get('key_type'):
        body['key_type'] = str(b['key_type'])
    if b.get('challenge'):
        body['challenge'] = str(b['challenge'])
    cid = A.cert_save(store, body, by, full=full, s=s)
    try:
        did = A.deploy_save(store, {'cert_id': cid, 'target': p['target'],
                                    'options': p['deploy']['options']}, by, full)
    except Exception:
        store.db.run('DELETE FROM certs WHERE id = ?', (cid,))
        raise
    store.add_event('certificates', 'the certificate found on %s (%s) was taken over by %s: '
                    'certificate %s, its deployment there' % (p['target'], p['where'], by,
                                                              p['cert']['name']), who=by)
    out = {'cert_id': cid, 'deploy_id': did, 'name': p['cert']['name'], 'job_id': None}
    if now:
        out['job_id'] = A.start_renew(store, cid, False, by)
    return out
