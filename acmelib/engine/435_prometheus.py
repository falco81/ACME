# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- Prometheus (1.0.173) ------------------------------------------------------------------
# https://NODE/metrics - each node's own, in Prometheus' text format: the
# database, the cluster and its replication, the certificates of the pages,
# the mail queue, isemon and syslog, the alerts open now - and what each
# module adds (HOOKS['metrics']: the certificates it keeps, its jobs). Asked
# with the token (Authorization: Bearer ...), kept sealed; from the networks
# set only, where any are. Off until switched on.
METRICS_TOKEN_RE = re.compile(r'^[A-Za-z0-9_.~+/=-]{24,200}\Z')


def _m_esc(v):
    return str(v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


class _Metrics(object):
    def __init__(self):
        self.out = []

    def put(self, name, kind, words, samples):
        """samples: [(labels dict, value)] - one family, said once."""
        samples = [(l, v) for l, v in samples if v is not None]
        if not samples:
            return
        self.out.append('# HELP %s %s' % (name, words))
        self.out.append('# TYPE %s %s' % (name, kind))
        for labels, v in samples:
            lab = ','.join('%s="%s"' % (k, _m_esc(x)) for k, x in sorted(labels.items()))
            self.out.append('%s%s %s' % (name, '{%s}' % lab if lab else '',
                                         repr(float(v)) if isinstance(v, float) else int(v)))

    def text(self):
        return '\n'.join(self.out) + '\n'


def metrics_text(daemon):
    store = daemon.store
    m = _Metrics()
    began = time.time()
    me = node_name()
    m.put('acme_info', 'gauge', 'This acme: its version, node and database engine.',
          [({'version': __version__, 'node': me, 'site': CONFIG.get('site_name') or short_host(),
             'engine': store.db.engine}, 1)])
    m.put('acme_start_time_seconds', 'gauge', 'When the daemon started (unix time).',
          [({}, float(daemon.started))])
    # The database: asked once, how long it took.
    t0 = time.time()
    try:
        store.db.value('SELECT 1')
        db_ok = 1
    except Exception:                                   # noqa: BLE001
        db_ok = 0
    m.put('acme_database_up', 'gauge', 'Whether the database answers.', [({}, db_ok)])
    m.put('acme_database_seconds', 'gauge', 'How long SELECT 1 took.',
          [({}, round(time.time() - t0, 6))])
    if not db_ok:
        return m.text()
    try:
        m.put('acme_directories', 'gauge', 'Directories (Active Directory).',
              [({}, len(daemon.dirs))])
        rows = store.db.rows("SELECT level, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY "
                             "level", (time.time() - 86400,))
        m.put('acme_events_last_day', 'gauge',
              'Events of the last 24 hours in the database (both nodes), by level.',
              [({'level': x['level'] or '?'}, x['n']) for x in rows])
    except Exception as e:                              # noqa: BLE001
        log_sparing('metrics-db', 'Prometheus: %s' % e, 'warn', every=600)
    # The cluster.
    if CONFIG.get('ha_mode'):
        try:
            nodes = ha_nodes(store)
            m.put('acme_ha_node_up', 'gauge', 'Whether each node was heard from lately.',
                  [({'node': n['name']}, 1 if n.get('alive') else 0) for n in nodes])
            m.put('acme_ha_heartbeat_age_seconds', 'gauge', 'Since each node was last heard from.',
                  [({'node': n['name']}, round(float(n.get('age') or 0), 1)) for n in nodes])
            rep = ha_repl_state(store)
            m.put('acme_ha_replication_running', 'gauge',
                  'Whether this node takes the other\'s rows (each subscription).',
                  [({'name': x['name']}, 1 if x.get('running') else 0)
                   for x in rep.get('incoming') or []])
            m.put('acme_ha_replication_errors_total', 'counter',
                  'Errors of this node taking the other\'s rows.',
                  [({'name': x['name']}, int(x.get('apply_errors') or 0) +
                    int(x.get('sync_errors') or 0)) for x in rep.get('incoming') or []])
            m.put('acme_ha_replication_behind_bytes', 'gauge',
                  'How far the other node is behind in taking this one\'s rows.',
                  [({'name': x['name']}, int(x.get('behind') or 0))
                   for x in rep.get('outgoing') or []])
        except Exception as e:                          # noqa: BLE001
            log_sparing('metrics-ha', 'Prometheus, the cluster: %s' % e, 'warn', every=600)
    # The certificates of the pages.
    try:
        certs = []
        for t in tls_targets(store):
            info = (tls_profile(store, t) or {}).get('info') or {}
            if info.get('not_after'):
                certs.append(({'target': 'vip' if t == 'vip' else t,
                               'name': info.get('cn') or ''}, float(info['not_after'])))
        m.put('acme_pages_certificate_expiry_timestamp_seconds', 'gauge',
              'When the certificate of the pages of each node and of the VIP address ends '
              '(unix time).', certs)
    except Exception:                                   # noqa: BLE001
        pass
    try:
        q = mailq_counts(store)
        m.put('acme_mail_queue', 'gauge', 'Mail waiting or failed, by state.',
              [({'state': k}, v) for k, v in sorted(q.items())])
    except Exception:                                   # noqa: BLE001
        pass
    for what, obj in (('isemon', getattr(daemon, 'shipper', None)),
                      ('siem', getattr(daemon, 'siem', None))):
        if not obj:
            continue
        st = obj.state()
        if not st.get('on'):
            continue
        m.put('acme_%s_sent_total' % what, 'counter', 'Lines sent since the daemon started.',
              [({'target': k}, v) for k, v in sorted((st.get('sent') or {}).items())] or
              [({'target': t}, 0) for t in st.get('targets') or []])
        m.put('acme_%s_trouble' % what, 'gauge', 'Whether a target is in trouble now.',
              [({'target': t}, 1 if t in (st.get('trouble') or {}) else 0)
               for t in st.get('targets') or []])
        m.put('acme_%s_dropped_total' % what, 'counter', 'Lines dropped, the queue full.',
              [({}, st.get('dropped') or 0)])
    try:
        probs = alert_problems(store, 'en')
        m.put('acme_alerts_open', 'gauge', 'What the alerts see wrong now, by level.',
              [({'level': lv}, sum(1 for p in probs.values() if p.get('level') == lv))
               for lv in ('bad', 'warn')])
        m.put('acme_alert', 'gauge', 'Each thing wrong now (1), with its key.',
              [({'key': k, 'level': p.get('level') or ''}, 1) for k, p in sorted(probs.items())])
    except Exception as e:                              # noqa: BLE001
        log_sparing('metrics-alerts', 'Prometheus, the alerts: %s' % e, 'warn', every=600)
    # What a module counts (HOOKS['metrics']): [(name, help, type, [(labels, value)])].
    for fn in HOOKS['metrics']:
        try:
            for name, words, kind, samples in list(fn(store) or []):
                if not re.match(r'^[a-zA-Z_:][a-zA-Z0-9_:]*\Z', str(name)):
                    continue
                m.put(str(name), 'counter' if kind == 'counter' else 'gauge', str(words),
                      [(dict(lab or {}), v) for lab, v in samples or []])
        except Exception as e:                          # noqa: BLE001
            log_sparing('metrics-hook', 'Prometheus, a module: %s: %s'
                        % (getattr(fn, '__qualname__', fn), e), 'warn', every=600)
    m.put('acme_high_security', 'gauge', 'Whether high security is on.',
          [({}, 1 if CONFIG.get('high_security') else 0)])
    m.put('acme_scrape_seconds', 'gauge', 'How long this answer took.',
          [({}, round(time.time() - began, 6))])
    return m.text()


def metrics_allowed(client):
    nets = [w for w in re.split(r'[\s,;]+', str(CONFIG.get('metrics_from') or '')) if w]
    if not nets:
        return True
    try:
        a = ipaddress.ip_address(str(client or '').strip('[]'))
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


@route('GET', '/api/metrics')
def _metrics(h):
    """What metrics.php asks, with the scraper's token - not a session."""
    if not CONFIG.get('metrics'):
        raise ApiError(404, 'Prometheus metrics are off (Settings → Monitoring)')
    want = unseal_secret(CONFIG.get('metrics_token') or '') or ''
    given = str(h.headers.get('X-Acme-Metrics') or '')
    if not want or not hmac.compare_digest(given.encode(), want.encode()):
        raise ApiError(401, 'the token is not the one set (Authorization: Bearer ...)')
    if not metrics_allowed(h.client_ip()):
        raise ApiError(403, 'not from the networks Prometheus may ask from')
    # The same answer for 10 s (1.0.186): two Prometheus servers, or one asking
    # every few seconds, each made the whole count again.
    with METRICS_CACHE['lock']:
        if time.time() - METRICS_CACHE['at'] > 10 or not METRICS_CACHE['text']:
            METRICS_CACHE['text'] = metrics_text(h.d)
            METRICS_CACHE['at'] = time.time()
        return {'text': METRICS_CACHE['text']}


METRICS_CACHE = {'at': 0.0, 'text': '', 'lock': threading.Lock()}


@route('POST', '/api/metrics')
def _metrics_do(h):
    """A new token (shown once), and what the scrape looks like now."""
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'token':
        tok = secrets.token_urlsafe(32)
        h.d.save_settings({'metrics_token': tok}, by=s['name'])
        h.store.add_event('settings', '%s made a new token for Prometheus - the one before no '
                          'longer opens /metrics' % s['name'], 'warn', who=s['name'])
        return {'token': tok}
    if act == 'preview':
        return {'text': metrics_text(h.d)}
    raise ApiError(400, 'no such thing to do')


