# -*- coding: utf-8 -*-
"""
HTTP-01 answered by acme itself (validation kind http_local): how it works on
this installation, said plainly - for the validation's popup and row
(GET /api/validations/info), `acme --validation-show NAME`, and the "Check a
name" action (POST /api/validations/check).

    info(store, row)     the URL the CA fetches, the machines that answer it now (every
                         node with its address, the VIP address with its name), port 80 in
                         their firewall, and each name of the certificates that use the
                         validation with what it resolves to - one of acme's addresses or not
    check(store, row, name, by)   a probe token put in place and fetched over HTTP at
                         http://NAME/.well-known/acme-challenge/<token>, from here, as the
                         CA would - each step written down in a job
"""
from __future__ import annotations

import binascii
import json
import os
import socket
import threading

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import jobs, runtime

PATH = '/.well-known/acme-challenge/'
KINDS = ('http_local',)
MOST_NAMES = 60


def _resolve(name, timeout=3.0):
    """[addresses] of a name (A and AAAA), [] when it has none - asked in a
    thread of its own so a DNS that does not answer holds nothing long."""
    got = {'a': None}

    def ask():
        try:
            got['a'] = sorted({i[4][0] for i in socket.getaddrinfo(name, 80, 0,
                                                                     socket.SOCK_STREAM)})
        except (OSError, UnicodeError, ValueError):
            got['a'] = []
    t = threading.Thread(target=ask, name='acme-http01-resolve', daemon=True)
    t.start()
    t.join(timeout)
    return got['a'] if got['a'] is not None else None


def _plain(addr):
    return str(addr or '').split('/')[0].split('%')[0].strip()


def machines(store):
    """{'nodes': [{name, dns, address, alive, me, vip_here}], 'vip': {...},
    'addresses': {address: what}} - what answers port 80 now."""
    nodes = []
    try:
        beats = E.ha_nodes(store)
    except Exception:                                   # noqa: BLE001
        beats = []
    seen = set()
    for n in beats:
        if not E.CONFIG.get('ha_mode') and not n.get('me'):
            continue
        dns = ''
        try:
            dns = E.acme_name_of(store, n['name'])
        except Exception:                               # noqa: BLE001
            pass
        nodes.append({'name': n['name'], 'dns': dns or '', 'address': _plain(n.get('address')),
                      'alive': bool(n.get('alive')), 'me': bool(n.get('me')),
                      'vip_here': bool((n.get('web') or {}).get('vip_here'))})
        seen.add(n['name'])
    me = E.node_name()
    if me not in seen:
        try:
            dns = E.acme_name_of(store, me)
        except Exception:                               # noqa: BLE001
            dns = ''
        nodes.insert(0, {'name': me, 'dns': dns or '', 'address': _plain(E.node_address()),
                         'alive': True, 'me': True, 'vip_here': False})
    v = {}
    try:
        v = E.vip_conf(store) or {}
    except Exception:                                   # noqa: BLE001
        pass
    vip = {'on': bool(v.get('on')) and bool(E.CONFIG.get('ha_mode') or v.get('on')),
           'fqdn': str(v.get('fqdn') or ''), 'address': _plain(v.get('address')),
           'address6': _plain(v.get('address6')),
           'holder': next((n['name'] for n in nodes if n['vip_here']), '')}
    addrs = {}
    for n in nodes:
        if n['address']:
            addrs[n['address']] = 'node %s' % n['name']
    if vip['on']:
        for a in (vip['address'], vip['address6']):
            if a:
                addrs[a] = 'the VIP address'
    try:
        for a in E.local_addresses():
            a = _plain(a)
            if a and a not in addrs and not a.startswith(('127.', '::1', 'fe80')):
                addrs[a] = 'this node (%s)' % me
    except Exception:                                   # noqa: BLE001
        pass
    return {'nodes': nodes, 'vip': vip, 'addresses': addrs}


def firewall(store, nodes):
    """Port 80 on each node: [{node, managed, open, from_anywhere, why}]."""
    out = []
    try:
        managed = bool(E.fw_conf(store).get('on'))
    except Exception:                                   # noqa: BLE001
        managed = False
    for n in nodes:
        one = {'node': n['name'], 'managed': managed, 'open': True, 'from_anywhere': True,
               'item_on': True, 'exception': False, 'why': ''}
        if not managed:
            one['why'] = 'acme does not keep a firewall on this node: port 80 is as the ' \
                         'machine has it'
            out.append(one)
            continue
        try:
            items = E.fw_auto(store, n['name'])
        except Exception as e:                          # noqa: BLE001
            one.update(open=None, from_anywhere=None, why='could not be read: %s' % e)
            out.append(one)
            continue
        web = next((x for x in items if x['key'] == 'web'), None)
        rules = (web or {}).get('rules') or []
        p80 = [r for r in rules if '80' in str(r.get('port') or '').split(',')]
        one['item_on'] = bool(web and web.get('on'))
        one['open'] = one['item_on'] and bool(p80)
        one['from_anywhere'] = one['open'] and any(not r.get('source') for r in p80)
        one['exception'] = one['open'] and any(not r.get('source') and r.get('port') == '80'
                                               for r in p80)
        if not one['item_on']:
            one['why'] = 'the card HTTP / HTTPS is switched off under What acme lets in by ' \
                         'itself: port 80 is open only by a rule of your own'
        elif one['exception']:
            one['why'] = 'the pages are kept to some networks, but port 80 is open from ' \
                         'anywhere for HTTP-01 and /pki/'
        elif one['from_anywhere']:
            one['why'] = 'open from anywhere (HTTP / HTTPS)'
        else:
            one['why'] = 'open only from the networks of Who may reach the pages'
        out.append(one)
    return out


def names_of(store, row):
    """[(name, certificate)] of the certificates that use the validation."""
    out = []
    want = row['name']
    for c in store.db.rows("SELECT id, name, names, challenge, challenge_map FROM certs "
                           "WHERE challenge = ? OR challenge_map LIKE ? ORDER BY name",
                           (want, '%' + json.dumps(want) + '%')):
        cmap = S.jload(c.get('challenge_map'), {}) or {}
        for n in S.jload(c.get('names'), []) or []:
            try:
                got = S.challenge_for(c, n)
            except Exception:                           # noqa: BLE001
                got = c.get('challenge') if n not in cmap else cmap.get(n)
            if got == want:
                out.append((n, c['name']))
    return out


def name_state(name, addrs, vip):
    """{name, addresses, ours, words} - where a name points, seen from here."""
    if name.startswith('*.'):
        return {'name': name, 'addresses': [], 'ours': False, 'wildcard': True,
                'words': 'a wildcard cannot be proved by HTTP-01: give it a DNS-01 validation'}
    got = _resolve(name)
    if got is None:
        return {'name': name, 'addresses': [], 'ours': None,
                'words': 'DNS did not answer in time'}
    if not got:
        return {'name': name, 'addresses': [], 'ours': False,
                'words': 'it has no address in DNS'}
    mine = [a for a in got if a in addrs]
    other = [a for a in got if a not in addrs]
    if mine and not other:
        return {'name': name, 'addresses': got, 'ours': True,
                'words': 'points at acme (%s)' % ', '.join('%s: %s' % (a, addrs[a]) for a in mine)}
    target = vip['address'] if vip.get('on') and vip.get('address') else ''
    return {'name': name, 'addresses': got, 'ours': False if not mine else None,
            'words': 'points elsewhere: %s - set its DNS to %s or put a proxy there that '
                     'forwards %s to acme' % (', '.join(other), (
                         'the VIP address %s' % target) if target else 'acme\'s address',
                         PATH)}


def info(store, row):
    """Everything the popup, the row and --validation-show say of an
    http_local validation. Other kinds: {'applies': False}."""
    if row.get('kind') not in KINDS:
        return {'applies': False, 'kind': row.get('kind')}
    m = machines(store)
    cls = S.plugin_class('challenge', row['kind'])
    cfg = S.plugin_config('challenge', row) if cls else {}
    pairs = names_of(store, row)
    names = []
    for n, cert in pairs[:MOST_NAMES]:
        one = name_state(n, m['addresses'], m['vip'])
        one['cert'] = cert
        names.append(one)
    fields = []
    for f in (getattr(cls, 'fields', None) or []):
        fields.append({'key': f['key'], 'label': f.get('label') or f['key'],
                       'value': cfg.get(f['key'], f.get('default')), 'help': f.get('help') or ''})
    return {'applies': True, 'kind': row['kind'], 'name': row['name'],
            'url': 'http://<NAME>' + PATH + '<token>', 'port': 80, 'scheme': 'http',
            'path': PATH, 'path_fixed': True,
            'nodes': m['nodes'], 'vip': m['vip'],
            'addresses': [{'address': a, 'what': w} for a, w in sorted(m['addresses'].items())],
            'firewall': firewall(store, m['nodes']), 'names': names,
            'names_more': max(0, len(pairs) - MOST_NAMES), 'fields': fields,
            'self_check': bool(cfg.get('self_check'))}


def check(store, row, name, by, echo=None):
    """A probe token answered by acme and fetched at http://NAME/... from here,
    in a job: {ok, said, job_id, steps}."""
    if row.get('kind') not in KINDS:
        raise ValueError('%s is not HTTP-01 answered by acme' % row['name'])
    cls = S.plugin_class('challenge', row['kind'])
    if cls is None:
        raise ValueError('the module http_local is not there')
    name = str(name or '').strip().lower().rstrip('.')
    m = machines(store)

    def fn(job):
        ctx = runtime.RunContext(store, job, scope='challenge:%s' % row['name'])
        inst = cls(S.plugin_config('challenge', row), ctx)
        try:
            n = inst.check_name(name)
            job.step('the CA would fetch http://%s%s<token> on port 80, plain HTTP' % (n, PATH))
            st = name_state(n, m['addresses'], m['vip'])
            job.step('%s: %s' % (n, st['words']), 'ok' if st['ours'] else 'warn')
            token = 'acme-probe-' + binascii.hexlify(os.urandom(12)).decode()
            ka = token + '.' + binascii.hexlify(os.urandom(12)).decode()
            ctx.http_token_put(token, ka)
            job.step('a probe token put in place (it lives an hour at most, and is taken away '
                     'at the end)')
            try:
                ok, words = inst.fetch('http://%s%s%s' % (n, PATH, token), ka)
            finally:
                try:
                    ctx.http_token_drop(token)
                except Exception:                       # noqa: BLE001
                    pass
            if ok:
                job.step(words, 'ok')
                return True, 'http://%s%s answers acme\'s probe - the CA will be answered' % (
                    n, PATH)
            job.step(words, 'bad')
            job.step('fetched from this node: where the name is acme\'s own public address '
                     'behind NAT, the router may not loop back (no hairpin NAT) although the '
                     'CA from outside would be answered - then switch "Check before the CA is '
                     'asked" off', 'info')
            return False, words
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'test', fn, by=by, said='HTTP-01 check of %s (%s)' % (
        name, row['name']), echo=echo)
    return {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps}
