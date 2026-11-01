# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- what it is doing --------------------------------------------------------------
@route('GET', '/api/status')
def _status(h):
    s = h.me()
    out = h.d.status()
    out['role'] = s['role']
    # The outgoing mail at a glance (1.0.95): what waits and what failed,
    # for the badge beside Mail. Counted at most every 10 s.
    now = time.time()
    if now - MAILQ_COUNT_CACHE[0] > 10:
        try:
            MAILQ_COUNT_CACHE[1] = mailq_counts(h.store)
        except Exception:                               # noqa: BLE001
            pass
        MAILQ_COUNT_CACHE[0] = now
    out['mailq'] = MAILQ_COUNT_CACHE[1]
    return out


MAILQ_COUNT_CACHE = [0.0, {}]
MAILQ_SEARCH_COLS = ('to_addr', 'state', 'kind', 'name', 'by_who', 'said', 'subject', 'tries',
                     'node')
MAILQ_SEARCH_TABLE = ('CREATE TABLE t (i INTEGER, to_addr TEXT, state TEXT, kind TEXT, '
                      'name TEXT, by_who TEXT, said TEXT, subject TEXT, tries INTEGER, node TEXT)')


def mailq_search_row(r):
    return {'to_addr': ' '.join(r.get('to') or []), 'state': r.get('state') or '',
            'kind': r.get('kind') or '', 'name': r.get('name') or '', 'by_who': r.get('by') or '',
            'said': r.get('said') or '', 'subject': mailq_subject_kept(r.get('subject'), r.get('kind')),
            'tries': int(r.get('tries') or 0), 'node': r.get('node') or ''}


@route('GET', '/api/software')
def _software(h):
    """What every node runs on (1.0.99): this one asked now, the others as
    their last heartbeat said."""
    h.me()
    me = node_name()
    out = [{'name': me, 'me': True, 'alive': True, 'software': software_info(h.store)}]
    try:
        for n in ha_nodes(h.store):
            if n['name'] != me:
                out.append({'name': n['name'], 'me': False, 'alive': bool(n.get('alive')),
                            'age': int(n.get('age') or 0), 'software': n.get('software') or {}})
    except Exception:                                   # noqa: BLE001
        pass
    return {'nodes': out}


@route('GET', '/api/mailq')
def _mailq(h):
    """The outgoing mail (1.0.95): what waits, what went, what failed."""
    h.me()
    q = h.arg('q')
    state = h.arg('state')
    every = mailq_all(h.store)
    rows = [r for r in every
            if (not state or r.get('state') == state or
                (state == 'open' and r.get('state') in ('waiting', 'sending', 'failed')))]
    # The same words as every list (1.0.96): fields, values, OR, NOT, ~.
    try:
        keep = memory_search('mailq', MAILQ_SEARCH_TABLE, MAILQ_SEARCH_COLS,
                             [mailq_search_row(r) for r in rows], q) if q.strip() else None
    except ListQueryError as e:
        return {'rows': [], 'total': 0, 'q_error': str(e),
                'counts': {k: 0 for k in MAILQ_STATES}, 'node': node_name(),
                'retry_hours': int(CONFIG.get('mail_retry_hours') or 24),
                'keep_days': int(CONFIG.get('mail_keep_days') or 14),
                'mode': CONFIG.get('mail_mode') or 'off'}
    if keep is not None:
        rows = [rows[i] for i in sorted(keep)]
    limit, offset = h.num('limit', 100, 1, 1000), h.num('offset', 0)
    counts = collections.Counter(r.get('state') for r in every)
    MAILQ_COUNT_CACHE[0] = 0
    return {'rows': [mailq_view(r) for r in rows[offset:offset + limit]], 'total': len(rows),
            'counts': {k: int(counts.get(k, 0)) for k in MAILQ_STATES},
            'node': node_name(), 'retry_hours': int(CONFIG.get('mail_retry_hours') or 24),
            'keep_days': int(CONFIG.get('mail_keep_days') or 14),
            'mode': CONFIG.get('mail_mode') or 'off'}


@route('GET', '/api/mailq/one')
def _mailq_one(h):
    h.me()
    rec, _raw = mailq_read(h.store, h.arg('id'))
    if not rec:
        raise ApiError(404, 'that mail is not in the outgoing mail any more')
    out = mailq_view(rec)
    out['history'] = rec.get('history') or []
    out['steps'] = rec.get('steps') or []
    out['has_body'] = bool(h.store.get_meta(MAILB_PREFIX + h.arg('id')))
    return out


@route('POST', '/api/mailq')
def _mailq_do(h):
    s = h.me('tokenadmin')
    b = h.body()
    act = str(b.get('action') or '')
    ids = b.get('ids') or []
    if not isinstance(ids, list) or not all(isinstance(x, str) and
                                            re.fullmatch(r'[0-9]{13}-[0-9a-f]{8}', x)
                                            for x in ids):
        raise ApiError(400, 'ids is a list of the mails\' own ids')
    if act in ('retry_all', 'drop_sent', 'drop_failed'):
        want = {'retry_all': ('waiting', 'failed'), 'drop_sent': ('sent',),
                'drop_failed': ('failed', 'expired')}[act]
        ids = [r['qid'] for r in mailq_all(h.store) if r.get('state') in want]
        act = 'retry' if act == 'retry_all' else 'drop'
    MAILQ_COUNT_CACHE[0] = 0
    if act == 'retry':
        if (CONFIG.get('mail_mode') or 'off') == 'off':
            raise ApiError(409, 'sending mail is switched off - Settings → Mail')
        done, skipped = mailq_retry(h.store, ids, s['name'])
        codes = MAILQ_RETRY_WHY.get('code', 0)
        rest = len(skipped) - codes
        msg = '%d mail(s) are being sent again now' % len(done)
        if codes:
            # Said for what it is (1.0.103): a code past its time.
            msg += ' - %d code(s) to sign in with are past their time and no good any more' % codes
        if rest:
            msg += ' - %d could not be (sent already, or what they held is gone)' % rest
        return {'done': len(done), 'skipped': len(skipped), 'message': msg}
    if act == 'drop':
        n = mailq_drop(h.store, ids, s['name'])
        return {'done': n, 'message': '%d mail(s) taken out of the outgoing mail' % n}
    raise ApiError(400, 'no such thing to do with the outgoing mail')


@route('GET', '/api/dashboard')
def _dashboard(h):
    h.me()
    return h.store.overview(h.num('hours', 24, 1, 24 * 400),
                            since=h.num('since', 0, 0, 10 ** 11) or None,
                            until=h.num('until', 0, 0, 10 ** 11) or None)


def list_query(listname, text):
    """(query, error words): what a search box asked, read as fields."""
    try:
        return ListQuery(listname, text), ''
    except ListQueryError as e:
        return None, str(e)


@route('GET', '/api/suggest')
def _suggest(h):
    """The fields of one list, or what one of them holds - what the search
    box over the list offers as somebody types (1.0.19)."""
    h.me()
    name = h.arg('list')
    if name not in LIST_FIELDS:
        raise ApiError(400, 'no such list')
    field = h.arg('field').lower()
    if not field:
        said = LIST_FIELD_SAYS.get(name) or LIST_FIELD_SAYS.get('radius')
        return {'fields': [list(f) for f in said]}
    hours = h.num('hours', 0, 0, 24 * 3650)
    # What the log held in the last 90 days when no time is given (1.0.101):
    # the whole log counted again on every key pressed was seconds a time.
    since = time.time() - (hours or 24 * 90) * 3600 if name in ('radius', 'acme', 'events') \
        else (time.time() - hours * 3600 if hours else 0)
    typed = h.arg('typed')[:120]
    if name == 'mailq':
        # Its rows are in no table: what the field holds, counted here.
        col = (LIST_FIELDS['mailq'].get(field) or ('', ''))[0]
        got = collections.Counter()
        for r in mailq_all(h.store):
            v = str(mailq_search_row(r).get(col) or '')
            for one in (v.split() if col == 'to_addr' else [v]):
                if one and (not typed or typed.strip('*').lower() in one.lower()):
                    got[one] += 1
        return {'values': [{'val': v, 'n': n} for v, n in got.most_common(15)]}
    if name == 'radius':
        # The Log is two lists in one: a field either of them holds.
        got = h.reader.list_values('radius', field, typed, since)
        more = h.reader.list_values('acme', field, typed, since)
        seen = {g['val'].lower(): g for g in got}
        for m in more:
            if m['val'].lower() in seen:
                seen[m['val'].lower()]['n'] += m['n']
            else:
                got.append(m)
        got.sort(key=lambda x: -x['n'])
        return {'values': got[:15]}
    return {'values': h.reader.list_values(name, field, typed, since)}


@route('GET', '/api/radius')
def _radius(h):
    h.me()
    lq, bad = list_query('radius', h.arg('q'))
    if bad:
        return {'rows': [], 'total': 0, 'q_error': bad, 'clients': []}
    rows, total = h.reader.radius_rows(
        hours=h.num('hours', 24, 1, 24 * 3650), q=lq.words, extra=(lq.sql, lq.args),
        result=h.arg('result'),
        client=h.arg('client'), limit=h.num('limit', 100, 1, 1000),
        offset=h.num('offset', 0), sort=h.arg('sort', 'ts'),
        desc=h.arg('desc', '1') != '0', user=h.arg('user'))
    return {'rows': rows, 'total': total,
            'clients': [c['name'] for c in h.store.clients()]}


@route('GET', '/api/activity')
def _activity(h):
    """The one log of the pages: every RADIUS request - with what the token
    said about its code - and every code checked anywhere else (the
    enrolment pages, a test, the command line), newest first."""
    h.me()
    hours = h.num('hours', 24, 1, 24 * 3650)
    q, kind, result = h.arg('q'), h.arg('kind'), h.arg('result')
    client = h.arg('client')
    limit, offset = h.num('limit', 100, 1, 1000), h.num('offset', 0, 0, 10 ** 9)
    if offset > 20000:
        # Said, not quietly turned into page 200 again (1.0.57).
        raise ApiError(400, 'that is further back than these pages go: narrow the time window '
                            'or the search')
    want = offset + limit
    out, total = [], 0
    rq, bad = list_query('radius', q)
    oq, bad2 = list_query('acme', q)
    if bad or bad2:
        return {'rows': [], 'total': 0, 'q_error': bad or bad2,
                'clients': [c['name'] for c in h.store.clients()]}
    # One hour of the chart, counted and paged here (1.0.36): picked out of
    # the first page in the browser, the count was the day's, and an older
    # hour came out empty.
    since, until = h.num('since', 0, 0, 10 ** 11), h.num('until', 0, 0, 10 ** 11)

    def span(sql, args):
        parts, args = ([sql] if sql else []), list(args or [])
        if since:
            parts.append('ts >= ?')
            args.append(since)
        if until:
            parts.append('ts < ?')
            args.append(until)
        return ' AND '.join('(%s)' % x for x in parts), args
    rq.sql, rq.args = span(rq.sql, rq.args)
    oq.sql, oq.args = span(oq.sql, oq.args)
    if kind != 'codes':
        rows, n = h.reader.radius_rows(hours=hours, q=rq.words, extra=(rq.sql, rq.args),
                                      result=result, client=client, limit=want, offset=0)
        total += n
        for r in rows:
            out.append({'kind': 'radius', 'id': r['id'], 'ts': r['ts'], 'name': r.get('username'),
                        'realm': r.get('realm'), 'result': r.get('result'),
                        'why': r.get('reason') or r.get('acme') or '',
                        'code': r.get('acme') or '', 'source': r.get('client') or '',
                        'from': r.get('calling') or r.get('src') or '',
                        'device': r.get('device') or '', 'ms': r.get('took_ms'),
                        'node': r.get('node') or ''})
    if kind != 'radius' and not client and result in ('', 'access', 'accept', 'reject'):
        ok = None if result in ('', 'access') else result == 'accept'
        rows, n = h.reader.acme_rows(hours=hours, q=oq.words, ok=ok, limit=want, offset=0,
                                   not_how='radius', extra=(oq.sql, oq.args))
        total += n
        for r in rows:
            out.append({'kind': 'code', 'id': r['id'], 'ts': r['ts'], 'name': r.get('name'),
                        'result': 'accept' if r.get('ok') else 'reject',
                        'why': r.get('said') or '', 'code': r.get('said') or '',
                        'source': r.get('how') or '', 'from': r.get('src') or '',
                        'device': '', 'ms': None, 'rid': r.get('rid') or '',
                        'node': r.get('node') or ''})
    out.sort(key=lambda x: (x['ts'] or 0, x['id']), reverse=True)
    return {'rows': out[offset:offset + limit], 'total': min(total, 20000 + limit),
            'more_than': total > 20000 + limit,
            'clients': [c['name'] for c in h.store.clients()]}


@route('GET', '/api/radius/row')
def _radius_row(h):
    h.me()
    r = h.store.radius_row(h.num('id', 0))
    if not r:
        raise ApiError(404, 'there is no such request')
    return {'row': r}


@route('GET', '/api/acme')
def _acme(h):
    h.me()
    ok = h.arg('ok')
    rows, total = h.store.acme_rows(hours=h.num('hours', 24, 1, 24 * 3650), q=h.arg('q'),
                                   ok=None if ok == '' else ok == '1',
                                   limit=h.num('limit', 100, 1, 1000),
                                   offset=h.num('offset', 0), name=h.arg('name'))
    return {'rows': rows, 'total': total}


