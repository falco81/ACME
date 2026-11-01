# -*- coding: utf-8 -*-
"""
Settings → DNS: the named sets of DNS servers and which of them each function
of acme asks (acmelib/certs/dnssets.py, docs/dns-sets.md) - the routes the
pages ask, and the command line.

    GET  /api/dnssets           the sets ("The system's" first), the functions
                                with the set each asks and why, where each set
                                is used, the protocols                (read-only)
    POST /api/dnssets/save      {name, old_name?, servers, protocol, tls_name,
                                timeout, note}: a set added or changed (full)
    POST /api/dnssets/delete    {name}: a set deleted (full)
    POST /api/dnssets/assign    {purpose, set}: a function given a set, '' for
                                its default (full)
    POST /api/dnssets/test      {name, qname, qtype}: a name looked up through a
                                set kept (read-only); with `servers` and the rest
                                of a set's fields, through a set not saved yet (full)
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import dnssets as N


@A.api('GET', '/api/dnssets')
def _list(h, s):
    got = N.summary(h.store)
    got['can_change'] = s.get('role') == 'fulladmin'
    return got


@A.api('POST', '/api/dnssets/save', 'fulladmin')
def _save(h, s):
    b = h.body()
    got = N.save_set(h.store, b, A.who(s))
    return {'set': got, 'message': 'the DNS set %s was saved' % got['name']}


@A.api('POST', '/api/dnssets/delete', 'fulladmin')
def _delete(h, s):
    got = N.delete_set(h.store, h.body().get('name'), A.who(s))
    got['message'] = 'the DNS set %s was deleted' % got['deleted']
    return got


@A.api('POST', '/api/dnssets/assign', 'fulladmin')
def _assign(h, s):
    b = h.body()
    got = N.assign(h.store, str(b.get('purpose') or ''), b.get('set'), A.who(s))
    got['message'] = 'names are looked up through %s' % got['set']
    return got


@A.api('POST', '/api/dnssets/test')
def _test(h, s):
    b = h.body()
    if b.get('servers') not in (None, '', []) and s.get('role') != 'fulladmin':
        raise A.E.ApiError(403, 'a set not saved is tried by a full administrator')
    return {'test': N.test(h.store, b)}


# ---------------------------------------------------------------------------
# The command line: --dns-sets, --dns-set-add NAME --servers a,b, --dns-set-edit,
# --dns-set-del, --dns-set-test NAME QNAME [TYPE], --dns-assign FUNCTION SET
# ---------------------------------------------------------------------------
def _fields(a, base=None):
    b = dict(base or {})
    if a.servers is not None:
        b['servers'] = a.servers
    if a.protocol:
        b['protocol'] = a.protocol
    if a.tls_name is not None:
        b['tls_name'] = a.tls_name
    if a.dns_timeout is not None:
        b['timeout'] = a.dns_timeout
    if a.note:
        b['note'] = a.note
    return b


def cli(c):
    a, store, by = c.args, c.store, c.WHO
    N.ensure(store)
    try:
        if a.dns_set_add:
            if not a.servers:
                raise SystemExit('acme: --dns-set-add NAME --servers ADDR,ADDR')
            if any(x['name'] == a.dns_set_add for x in N.sets(store)):
                raise SystemExit('acme: there is a DNS set %s already (--dns-set-edit)'
                                 % a.dns_set_add)
            got = N.save_set(store, _fields(a, {'name': a.dns_set_add}), by)
            return c.done('the DNS set %s was added: %s' % (got['name'], ', '.join(
                got['servers'])), {'ok': True, 'set': got})
        if a.dns_set_edit:
            have = [x for x in N.sets(store) if x['name'] == a.dns_set_edit]
            if not have:
                raise SystemExit('acme: there is no DNS set %s' % a.dns_set_edit)
            base = dict(have[0], old_name=a.dns_set_edit, name=a.name or a.dns_set_edit)
            got = N.save_set(store, _fields(a, base), by)
            return c.done('the DNS set %s was changed' % got['name'], {'ok': True, 'set': got})
        if a.dns_set_del:
            c.sure('delete the DNS set %s' % a.dns_set_del)
            got = N.delete_set(store, a.dns_set_del, by)
            return c.done('the DNS set %s was deleted%s' % (
                a.dns_set_del, ('; back to their default: %s' % ', '.join(
                    got['back_to_default'])) if got['back_to_default'] else ''), got)
        if a.dns_assign:
            fn, name = a.dns_assign
            got = N.assign(store, fn, '' if name in ('default', '-') else name, by)
            return c.done('%s: names are looked up through %s' % (fn, got['set']), got)
        if a.dns_set_test:
            w = a.dns_set_test
            if len(w) not in (2, 3):
                raise SystemExit('acme: --dns-set-test NAME QNAME [TYPE]')
            got = N.test(store, {'name': w[0], 'qname': w[1],
                                 'qtype': w[2] if len(w) > 2 else 'A'})
            if c.json:
                c.out(got)
                return 0 if got['ok'] else 1
            print('  %s %s through %s (%s)' % (got['qname'], got['qtype'], got['set'],
                                              N.PROTOCOLS[got['protocol']]))
            for t in got['tries']:
                line = '%-24s %5d ms  %s' % (t['server'], t['ms'], t['said'])
                print('  ' + (c.pal.ok_line(line) if t['ok'] else c.pal.bad_line(line)))
                for r in t['answers']:
                    print('      %s %s %s %s' % (r['name'], r['ttl'], r['type'], r['value']))
            if got['answered_by']:
                print('  answered by %s' % got['answered_by'])
            return 0 if got['ok'] else 1
    except (ValueError, LookupError) as e:
        raise SystemExit('acme: %s' % e)
    got = N.summary(store)
    if c.json:
        c.out(got)
        return 0
    print('DNS sets')
    c.table([[x['name'], ', '.join(x['servers']), N.PROTOCOLS.get(x['protocol'], ''),
              '%g s' % x['timeout'], ', '.join(got['used'].get(x['name'], [])) or '-']
             for x in got['sets']], ['set', 'servers', 'protocol', 'timeout', 'used for'])
    print('\nFunctions')
    c.table([[p['key'], p['title'], p['set'], {'assigned': 'chosen', 'legacy': 'set before',
                                               'default': 'its default'}[p['how']]]
             for p in got['purposes']], ['function', 'what', 'asks', 'why'])
    return 0
