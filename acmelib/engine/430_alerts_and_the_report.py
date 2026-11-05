# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- alerts and the report on the pages (1.0.162) --------------------------------------
def _report_span(which):
    """The period asked for: the last one ended, or the one going on so far."""
    since, until, _ = report_period()
    if which == 'now':
        return until, time.time()
    return since, until


@route('GET', '/api/alerts')
def _alerts(h):
    h.me('fulladmin')
    return alerts_view(h.store)


@route('POST', '/api/alerts')
def _alerts_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    lang = alerts_lang()
    try:
        if act == 'check':
            # looked at and sent by the lead node only (1.0.52): the other one's pages mailed
            # too, and wrote its own older copy of what was said over the lead's
            if alerts_lead(h.store):
                alerts_evaluate(h.store)
            return alerts_view(h.store)
        if act == 'test':
            to = _alerts_to()
            if not to:
                raise ValueError('no address to send it to - Send them to')
            now = alert_problems(h.store, lang)
            msg = alert_mail([], [dict(p, key=k) for k, p in now.items()], [], [], to, lang,
                             test=True)
            entry = alert_send(h.store, msg, to, 'test', [])
            h.store.add_event('settings', '%s sent a test alert to %s%s' % (
                s['name'], ', '.join(to), '' if entry['ok'] else ' - %s' % entry.get('said')),
                'info', who=s['name'])
            if not entry['ok'] and entry.get('queued') != 'waiting':
                raise ValueError('it did not go: %s' % entry.get('said'))
            return dict(alerts_view(h.store), message='a test alert went to %s' % ', '.join(to)
                        if entry['ok'] else 'it waits in the outgoing mail: %s' % entry.get('said'))
        if act == 'preview':
            since, until = _report_span(str(b.get('period') or 'last'))
            subject, page, _ = report_build(h.reader, since, until, report_lang())
            return {'subject': subject, 'html': page}
        if act == 'report':
            since, until = _report_span(str(b.get('period') or 'last'))
            entry = report_send(h.store, since, until, by=s['name'], reader=h.reader)
            if not entry['ok'] and entry.get('queued') != 'waiting':
                raise ValueError('it did not go: %s' % entry.get('said'))
            return dict(alerts_view(h.store), message='the report went to %s' % ', '.join(entry['to'])
                        if entry['ok'] else 'it waits in the outgoing mail: %s' % entry.get('said'))
        if act == 'forget':
            # On the node that sends only (as otp 1.0.234): written from another node's older
            # copy, the whole row took back what the sending node had said - the same alerts again.
            if not alerts_lead(h.store):
                raise ValueError('only the node that sends the alerts keeps what was sent - '
                                 'forget it on that node\'s pages')
            st = _alert_state(h.store)
            st['log'] = []
            h.store.set_meta('alerts:state', json.dumps(st))
            return alerts_view(h.store)
    except (ValueError, MailError) as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


# ---- syslog / SIEM, the proxy, the disks and the logs (1.0.166) -------------------------
def _siem_view(h):
    nodes = [n['name'] for n in ha_nodes(h.store)] if CONFIG.get('ha_mode') else [node_name()]
    me = h.d.siem.state() if getattr(h.d, 'siem', None) else {}
    out = []
    for n in nodes:
        row = _meta_obj(h.store, 'host:health:' + n)
        st = me if n == node_name() else (row.get('siem') or {})
        out.append(dict(st, node=n, me=n == node_name(), at=time.time() if n == node_name()
                        else row.get('at')))
    return {'nodes': out, 'on': bool(CONFIG.get('siem'))}


@route('GET', '/api/siem')
def _siem(h):
    h.me('fulladmin')
    return _siem_view(h)


@route('POST', '/api/siem')
def _siem_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'result':
        return {'nodes': node_ask_results(h.store, 'siem', str(b.get('id') or ''))}
    if act != 'test':
        raise ApiError(400, 'no such thing to do')
    if not CONFIG.get('siem') or not siem_targets(CONFIG.get('siem_targets')):
        raise ApiError(400, 'no syslog server is set')
    # From every node (1.0.169): each sends its own and says how it went.
    h.store.add_event('settings', '%s sent a test line to the syslog servers from every node'
                      % s['name'], 'info', who=s['name'])
    return node_ask(h.d, 'siem', {'by': s['name'], 'only': str(b.get('node') or '')}, s['name'])


@route('POST', '/api/proxy')
def _proxy_do(h):
    h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'try':
            # On every node (1.0.169); 'result' says what each found so far.
            url = str(b.get('url') or '').strip()
            if url and not re.match(r'^https?://[^\s/]+[^\s]*\Z', url):
                raise ValueError('an address starting https:// (or http://)')
            return node_ask(h.d, 'proxy', {'url': url}, h.me('fulladmin')['name'])
        if act == 'result':
            return {'nodes': node_ask_results(h.store, 'proxy', str(b.get('id') or ''))}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/logs')
def _logs(h):
    h.me('fulladmin')
    return logs_view(h.store)


@route('POST', '/api/logs')
def _logs_do(h):
    h.me('fulladmin')
    b = h.body()
    if str(b.get('action') or '') != 'refresh':
        raise ApiError(400, 'no such thing to do')
    # Every node asks its helper again at its next look (a minute at most);
    # this one at once.
    h.store.set_meta('host:logs:again', '%.3f' % time.time())
    try:
        logs_tick(h.d, force=True)
    except Exception as e:                              # noqa: BLE001
        raise ApiError(400, 'it did not go: %s' % e)
    return logs_view(h.store)


# ---- certificates by ACME (1.0.169) ---------------------------------------------------
@route('GET', '/api/acme/challenge')
def _acme_challenge(h):
    """What acme.php gives the CA on port 80 - no account: the CA asks."""
    got = acme_challenge(h.store, h.arg('token'))
    if got is None:
        raise ApiError(404, 'no such challenge')
    return {'auth': got}


@route('GET', '/api/acme/file')
def _acme_file(h):
    """A commercial CA's DCV file that acme.php gives on port 80 - no account."""
    got = acme_file(h.store, h.arg('host'), h.arg('path'))
    if got is None:
        raise ApiError(404, 'no such file')
    return {'content': got}


@route('GET', '/api/acme')
def _acme(h):
    h.me('fulladmin')
    return acme_view(h.store)


@route('POST', '/api/acme')
def _acme_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'order':
            if not CONFIG.get('acme'):
                raise ValueError('certificates by ACME are off - switch them on and save first')
            # Any of them from any node (1.0.170): the CA's question and the
            # certificate are kept in the database, and the node it is for -
            # every node, for the VIP address - puts it in. Ordered by hand,
            # ACME looks after it from now on.
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store) or \
                    (target == 'vip' and not vip_conf(h.store).get('address')):
                raise ValueError('there is no such certificate')
            name = acme_name_of(h.store, target)
            if not name:
                raise ValueError('the name of this certificate is not known - give it (Its name…)')
            acme_care_set(h.store, target, True, s['name'], 'ordered by hand')
            acme_start(h.store, [(target, name)], s['name'])
            return dict(acme_view(h.store), message='the certificate of %s is being ordered' % name)
        if act == 'order_all':
            # Every certificate asked for at once (1.0.200), one after another in
            # the one thread that orders: the same as Order it now on each card.
            if not CONFIG.get('acme'):
                raise ValueError('certificates by ACME are off - switch them on and save first')
            which, left = [], []
            # The ones chosen in the window (1.0.200); none given: all of them.
            chosen = b.get('targets')
            if chosen is not None and not isinstance(chosen, list):
                raise ValueError('targets is a list')
            for target in acme_wanted(h.store):
                if chosen is not None and target not in [str(x) for x in chosen]:
                    continue
                if target == 'vip' and not vip_conf(h.store).get('address'):
                    continue
                name = acme_name_of(h.store, target)
                if name:
                    which.append((target, name))
                else:
                    left.append(target)
            if not which:
                raise ValueError('none chosen' if chosen is not None and not left else
                                 'no certificate has a name to order it for - give one (Its name…)')
            for target, _n in which:
                acme_care_set(h.store, target, True, s['name'], 'ordered by hand')
            acme_start(h.store, which, s['name'])
            how = 'one after another' if acme_parallel_why(which) else 'side by side'
            return dict(acme_view(h.store), message='%d certificate(s) being ordered, %s: %s%s' % (
                len(which), how, ', '.join(n for _t, n in which),
                ('; no name for ' + ', '.join(left)) if left else ''))
        if act == 'dns_check':
            return acme_dns_check(h.store)
        if act == 'put_back':
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store):
                raise ValueError('there is no such certificate')
            acme_put_back(h.store, target, s['name'])
            return dict(acme_view(h.store), message='the certificate from before ACME is back; '
                        'the nodes put it in within a few seconds')
        if act == 'care':
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store):
                raise ValueError('there is no such certificate')
            acme_care_set(h.store, target, bool(b.get('on')), s['name'])
            return acme_view(h.store)
        if act == 'probe':
            return acme_reach_probe(h.store, str(b.get('target') or ''))
        if act == 'name':
            # Every certificate's name from one page (1.0.170): the other
            # node's and the VIP address's too, not only this node's.
            target = str(b.get('target') or '')
            name = str(b.get('name') or '').strip().lower().rstrip('.')
            if name and not re.match(r'^(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+'
                                     r'[a-z]{2,63}\Z', name):
                raise ValueError('%s is not a full DNS name (like acme2.example.cz)' % name[:80])
            if target == 'vip':
                if not vip_conf(h.store).get('address'):
                    raise ValueError('the VIP address is not set up (Settings → High availability)')
                vip_set(h.store, s['name'], fqdn=name)
            elif target in tls_targets(h.store):
                h.d.save_settings({'acme_node_name': name}, by=s['name'], node=target)
            else:
                raise ValueError('there is no such certificate')
            h.store.add_event('settings', '%s: the certificate of %s is for %s' % (
                s['name'], 'the VIP address' if target == 'vip' else target,
                name or 'its full host name'), who=s['name'])
            return acme_view(h.store)
        if act in ('manual_done', 'manual_drop'):
            # The TXT record put in by hand (1.0.169) - or the order given up.
            got = _meta_obj(h.store, 'acme:manual')
            if not got.get('id'):
                raise ValueError('no order waits for a TXT record now')
            if act == 'manual_done':
                got['done'] = time.time()
                h.store.set_meta('acme:manual', json.dumps(got))
            else:
                h.store.db.run("DELETE FROM meta WHERE k = 'acme:manual'")
            h.store.add_event('settings', '%s said the TXT record %s %s' % (
                s['name'], got.get('rr'), 'is in DNS' if act == 'manual_done' else
                'will not be put in - the order is given up'), who=s['name'])
            return acme_view(h.store)
        if act == 'forget':
            h.store.db.run("DELETE FROM meta WHERE k = 'acme:account'")
            h.store.add_event('settings', '%s forgot the account at the ACME CA - a new one is '
                              'made at the next order' % s['name'], 'warn', who=s['name'])
            return acme_view(h.store)
    except (ValueError, AcmeError) as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/dbtls')
def _dbtls(h):
    h.me('fulladmin')
    return dbtls_view(h.store)


@route('POST', '/api/dbtls')
def _dbtls_do(h):
    """The wizard of Encryption to the database server (1.0.170): 'probe' and
    'apply' asked of every node, 'result' what each said so far."""
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'result':
        kind = 'dbtls_probe' if b.get('of') == 'probe' else 'dbtls_apply'
        return {'nodes': node_ask_results(h.store, kind, str(b.get('id') or '')),
                'view': dbtls_view(h.store)}
    mode = str(b.get('mode') or '')
    if mode not in DBTLS_MODES:
        raise ApiError(400, 'the mode is require, verify-ca or verify-full')
    src = str(b.get('ca_source') or 'given')
    if src not in ('given', 'system', 'acme', 'keep'):
        raise ApiError(400, 'the authority is given, the system\'s, acme\'s or the one kept')
    pem = str(b.get('ca_pem') or '').strip()
    if pem and (len(pem) > 20000 or not re.match(
            r'^(-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\s*)+\Z',
            pem)):
        raise ApiError(400, 'the server\'s authority is one or more PEM certificates')
    args = {'mode': mode, 'ca_source': src, 'ca_pem': pem, 'by': s['name'],
            'only': str(b.get('node') or '')}
    if act == 'probe':
        return node_ask(h.d, 'dbtls_probe', args, s['name'])
    if act != 'apply':
        raise ApiError(400, 'no such thing to do')
    phase = str(b.get('phase') or '')
    if phase not in ('server', 'connect', 'server_off'):
        raise ApiError(400, 'the phase is server, connect or server_off')
    if phase == 'connect' and mode not in ('verify-ca', 'verify-full') and \
            dbtls_kind() not in ('sqlite', 'socket') and hisec_enforced('db:tls', h.store):
        raise ApiError(409, 'high security is on: the database is reached with TLS that checks '
                       'its certificate (verify-ca or verify-full) - or make db:tls an '
                       'exception there first')
    args.update(phase=phase, renew=bool(b.get('renew')))
    h.store.add_event('settings', '%s: encryption to the database server - %s%s' % (
        s['name'], {'server': 'the certificates of the PostgreSQLs on the nodes',
                    'connect': 'every node\'s connection to %s' % (mode or 'no TLS'),
                    'server_off': 'acme\'s certificates out of the PostgreSQLs'}[phase],
        (' (only %s)' % args['only']) if args['only'] else ''), 'info', who=s['name'])
    return node_ask(h.d, 'dbtls_apply', args, s['name'])


