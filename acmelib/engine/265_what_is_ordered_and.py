# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- what is ordered, and when ----------------------------------------------------------
def acme_name_of(store, target):
    """The DNS name a target's certificate is for."""
    if target == 'vip':
        return str(vip_conf(store).get('fqdn') or '').strip()
    k = 'acme_node_name@' + target
    saved = store.settings_saved()
    name = str(saved.get(k) or (CONFIG.get('acme_node_name') if target == node_name() else '')
               or '').strip()
    if not name and target == node_name():
        name = fqdn_cached()
    if not name:
        # The name of the certificate it has now (1.0.170) - what Certificates
        # and TLS shows: acme2's card said "for -" beside acme2.example.cz.
        info = (tls_profile(store, target) or {}).get('info') or {}
        for n in [info.get('cn')] + list(info.get('san') or []):
            n = str(n or '').strip().lower()
            if re.match(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\Z', n):
                name = n
                break
    if not name and target == node_name():
        name = fqdn_cached()
    elif not name and target != 'vip':
        # Another node's own name, as that node publishes it (1.0.170): its
        # card said "for -" and Try port 80 asked http://?/.
        name = str((_meta_json(store, 'acme:host:' + target) or {}).get('fqdn') or '').strip()
    return name


FQDN_CACHE = {'name': '', 'at': 0.0, 'asking': False}


def fqdn_cached():
    """This machine's full name, asked of DNS in a thread of its own and kept for
    ten minutes (1.0.207): socket.getfqdn() waits on a DNS that does not answer -
    20 s and more, twice a loop - and the main loop's heartbeat went late until
    the other node took this one for gone. The host name meanwhile."""
    now = time.monotonic()
    if (not FQDN_CACHE['at'] or now - FQDN_CACHE['at'] > 600) and not FQDN_CACHE['asking']:
        FQDN_CACHE['asking'] = True

        def ask():
            try:
                FQDN_CACHE['name'] = socket.getfqdn() or ''
            except Exception:                           # noqa: BLE001
                pass
            finally:
                FQDN_CACHE['at'] = time.monotonic()
                FQDN_CACHE['asking'] = False
        threading.Thread(target=ask, name='acme-fqdn', daemon=True).start()
    return FQDN_CACHE['name'] or socket.gethostname()


def acme_before(store, target):
    """The certificate a target had before ACME replaced it, as the page may
    see it (no key)."""
    got = _meta_json(store, 'acme:before:' + target) or {}
    if not got.get('cert'):
        return None
    info = got.get('info') or {}
    return {'how': got.get('how'), 'subject': info.get('subject'), 'issuer': info.get('issuer'),
            'not_after': info.get('not_after'), 'at': got.get('at'),
            'ran_out': float(info.get('not_after') or 0) < time.time()}


def acme_put_back(store, target, by):
    """The certificate from before ACME back in place, ACME no longer renewing
    it; its TLS settings (protocols, ciphers, DH, HSTS) stay as they are now."""
    got = _meta_json(store, 'acme:before:' + target) or {}
    if not got.get('cert'):
        raise ValueError('there is no certificate from before ACME for this one')
    info = got.get('info') or {}
    if float(info.get('not_after') or 0) < time.time():
        raise ValueError('the certificate from before ACME ran out on %s - put a new one in on '
                         'Certificates and TLS' % stamp(info.get('not_after')))
    prof = tls_profile(store, target) or {}
    prof.update({k: got.get(k) for k in ('cert', 'chain', 'root', 'key', 'info', 'chain_info',
                                         'root_info', 'verify', 'how')})
    prof.pop('pending_key', None)
    prof.pop('csr', None)
    tls_save(store, target, prof, by)
    store.set_meta('acme:care:' + target, json.dumps({'on': False, 'at': time.time(), 'by': by}))
    store.db.run('DELETE FROM meta WHERE k = ?', ('acme:before:' + target,))
    store.add_event('settings', '%s put the certificate of %s from before ACME back (%s, until %s); '
                    'ACME no longer renews it' % (by, 'the VIP address' if target == 'vip' else
                                                  target, info.get('issuer') or '?',
                                                  stamp(info.get('not_after'))), 'warn', who=by)


def acme_care(store, target):
    """Whether ACME looks after this certificate (1.0.170). Said on either page;
    unsaid: yes for one from the CA, a self-signed one and none at all - never
    for one uploaded or answered to a request (a CA of your own): switching ACME
    on does not replace those."""
    got = _meta_json(store, 'acme:care:' + target)
    if got and 'on' in got:
        return bool(got['on'])
    prof = tls_profile(store, target) or {}
    how = str(prof.get('how') or '')
    return not prof.get('cert') or how == 'ACME' or how.startswith('self-signed')


def acme_care_set(store, target, on, by, why=''):
    was = acme_care(store, target)
    store.set_meta('acme:care:' + target, json.dumps({'on': bool(on), 'at': time.time(),
                                                     'by': by}))
    if was != bool(on) and CONFIG.get('acme'):
        store.add_event('settings', '%s: ACME %s the certificate of %s%s' % (
            by, 'looks after' if on else 'no longer renews', 'the VIP address' if target == 'vip'
            else target, (' - ' + why) if why else ''), 'info' if on else 'warn', who=by)


ACME_FQDN_SEEN = {'at': 0.0, 'fqdn': None}


def acme_host_publish(store):
    """This node's full name, for the cards of the other nodes - once in ten
    minutes, written only when it changed."""
    if time.time() - ACME_FQDN_SEEN['at'] < 600:
        return
    ACME_FQDN_SEEN['at'] = time.time()
    fqdn = socket.getfqdn()
    if fqdn == ACME_FQDN_SEEN['fqdn']:
        return
    store.set_meta('acme:host:' + node_name(), json.dumps({'fqdn': fqdn, 'at': time.time()}))
    ACME_FQDN_SEEN['fqdn'] = fqdn


def acme_targets(store):
    """[(target, name)] this node orders: the VIP address's on the lead, and
    its own where asked."""
    if not CONFIG.get('acme'):
        return []
    want = CONFIG.get('acme_for') or 'vip'
    out = []
    if want in ('vip', 'both') and vip_conf(store).get('on') and alerts_lead(store):
        out.append(('vip', acme_name_of(store, 'vip')))
    if want in ('node', 'both') or (want == 'vip' and not vip_conf(store).get('on')):
        out.append((node_name(), acme_name_of(store, node_name())))
    return [(t, n) for t, n in out if n and acme_care(store, t)]


def acme_wanted(store):
    """The certificates asked for at all (For), whichever node renews them."""
    want = CONFIG.get('acme_for') or 'vip'
    out = []
    for t in tls_targets(store):
        if t == 'vip':
            if want in ('vip', 'both') and vip_conf(store).get('on'):
                out.append(t)
        elif want in ('node', 'both') or (want == 'vip' and not vip_conf(store).get('on')):
            out.append(t)
    return out


def acme_state(store, target):
    return _meta_json(store, 'acme:state:' + target) or {}


def acme_due(store, target, name):
    """Why this certificate is to be ordered now, or ''."""
    st = acme_state(store, target)
    if st.get('failed_at') and time.time() - float(st['failed_at']) < ACME_RETRY and \
            st.get('name') == name:
        return ''
    prof = tls_profile(store, target) or {}
    info = prof.get('info') or {}
    if prof.get('how') != 'ACME' or st.get('name') != name:
        return 'not ordered yet for %s' % name
    # The CA's own window (ARI, 1.0.196), looked up every few hours: renewed at
    # a moment picked in it - early too, where the CA says so (a revocation).
    # Earlier only, never later than acme's own measure below: a window gone
    # wrong (a CA's mistake, a clock) does not let a certificate run out.
    ari = _meta_json(store, 'acme:ari:' + target) or {}
    if ari.get('pick') and ari.get('cert') == (info.get('fingerprint') or '') and \
            time.time() - float(ari.get('at') or 0) < 2 * 86400 and time.time() >= float(ari['pick']):
        return 'the CA\'s renewal window (%s - %s)' % (stamp(ari['start']), stamp(ari['end']))
    left = (float(info.get('not_after') or 0) - time.time()) / 86400
    days = float(CONFIG.get('acme_days') or 30)
    # A third of its life at most (1.0.187): a CA giving fewer days than
    # acme_days (short-lived certificates, a test CA) had every new one due
    # at once - ordered again every hour, until its limits refused them all.
    life = (float(info.get('not_after') or 0) - float(info.get('not_before') or 0)) / 86400
    if info.get('not_before') and life > 0:
        days = min(days, life / 3)
    if left < days:
        return '%d days left' % int(left)
    return ''


def acme_order(store, target, name, by, say=None):
    """One certificate ordered and put in; the state kept, an event written -
    and what was done on the way (1.0.175), for the card."""
    tell = say or (lambda t: None)
    steps = []

    def say(t):
        steps.append([round(time.time(), 1), str(t)[:300]])
        tell(t)
    if not re.match(r'^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                    r'(?:[A-Za-z]{2,63}|[Xx][Nn]--[A-Za-z0-9-]{1,59})\Z', name):   # .рф too (1.0.209)
        raise AcmeError('%s is not a name a CA gives a certificate for (a full DNS name)' % name)
    st = {'name': name, 'at': time.time(), 'by': by, 'ca': acme_directory_url(), 'steps': steps}
    a = None
    try:
        a = Acme(store)
        choice = str(CONFIG.get('acme_key') or 'dual')
        kinds = ACME_CERT_KEYS.get(choice) or ('ec',)
        prof = tls_profile(store, target) or {}
        replaces = ari_cert_id(prof.get('cert')) if prof.get('how') == 'ACME' else ''
        # Said only by the account that ordered it (1.0.199); one of before
        # this was kept is tried, and ordered again without it if refused.
        was = acme_state(store, target)
        if replaces and was.get('kid') and was['kid'] != a.kid:
            replaces = ''
        say('the key%s: %s' % ('s' if len(kinds) > 1 else '', ' + '.join(ACME_KEY_WORDS[k] for k in kinds)))
        key, chain = a.order([name], say, kinds[0], replaces)
        got = cert_bundle(chain, key)
        info = got['info']
        alt = None
        made = [kinds[0]]
        if len(kinds) > 1:
            # The second certificate (1.0.196, as Let's Encrypt advises): the name
            # is already proven, so the CA only signs - nginx offers it to the
            # clients that take it, RSA to the rest.
            say('a second certificate, with a %s key' % ACME_KEY_WORDS[kinds[1]])
            try:
                k2, c2 = a.order([name], say, kinds[1])
                g2 = cert_bundle(c2, k2)
                alt = {'cert': g2['cert'], 'chain': g2['chain'],
                       'key': seal_secret(g2['key'], 'web:tls'),
                       'info': g2['info'], 'for': tls_alt_for(got['cert'])}
                made.append(kinds[1])
            except (AcmeError, ValueError) as e:
                # The first one kept all the same (1.0.205): thrown away with it,
                # the CA's weekly limit for the name was spent on nothing, and
                # every retry refused for a week.
                say('the second certificate did not come (%s) - the %s one is put in alone'
                    % (str(e)[:200], ACME_KEY_WORDS[kinds[0]]))
                st['alt_said'] = str(e)[:300]
        # As it is now, not as it was when the order began (1.0.205): an order
        # takes minutes, an hour by hand - what was changed on Certificates and
        # TLS meanwhile is kept, and one no longer looked after is left alone.
        prof = tls_profile(store, target) or {}
        if not acme_care(store, target):
            raise AcmeError('ACME was told to leave this certificate alone while it was being '
                            'ordered - the new one is not put in')
        if prof.get('cert') and prof.get('how') != 'ACME':
            # The certificate it had - uploaded, from your own CA - kept to go
            # back to (1.0.172): ACME switched off or left alone, it is put
            # back with a click, its key as sealed as it was.
            store.set_meta('acme:before:' + target, json.dumps(
                {k: prof.get(k) for k in ('cert', 'chain', 'root', 'key', 'info', 'chain_info',
                                          'root_info', 'verify', 'how')}
                | {'at': time.time()}))
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=seal_secret(got['key'], 'web:tls'), info=info,
                    chain_info=got['chain_info'], root_info=got['root_info'],
                    verify=got['verify'], how='ACME')
        if alt:
            prof['alt'] = alt
        else:
            prof.pop('alt', None)
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        tls_save(store, target, prof, by)
        st['kid'] = a.kid or ''
        st.update(ok=True, not_after=info.get('not_after'), issuer=info.get('issuer'),
                  ordered_at=time.time(), keys=' + '.join(ACME_KEY_WORDS[k] for k in made))
        st['steps'] = steps[-25:]
        store.set_meta('acme:state:' + target, json.dumps(st))
        store.add_event('settings', 'a certificate for %s (%s) came from the CA, good until %s'
                        % (name, 'the VIP address' if target == 'vip' else target,
                           stamp(info.get('not_after')) if info.get('not_after') else '?'),
                        'info', who=by)
        return st
    except (AcmeError, ValueError, OSError) as e:
        if 'NXDOMAIN' in str(e) and (CONFIG.get('acme_challenge') or '') == 'dns-01':
            e = AcmeError('%s - the CA does not find the record: In your DNS → Check DNS, with '
                          'DNS servers for ACME set to public ones (1.1.1.1), shows where the way '
                          'to it stops (the CNAME, or the delegation of its zone)' % e)
        st.update(ok=False, failed_at=time.time(), said=str(e)[:600])
        old = acme_state(store, target)
        for k in ('not_after', 'issuer', 'ordered_at', 'kid'):
            if old.get(k):
                st[k] = old[k]
        st['steps'] = steps[-25:]
        store.set_meta('acme:state:' + target, json.dumps(st))
        store.add_event('settings', 'no certificate for %s came from the CA: %s' % (name, e),
                        'bad', who=by)
        raise AcmeError(str(e))
    finally:
        if a:
            a.close()


ACME_ARI = {'at': 0.0}
ACME_ARI_EVERY = float(os.environ.get('ACME_ACME_ARI_EVERY') or 6 * 3600)


def acme_ari_refresh(store):
    """Each certificate this node orders: the CA's window to renew it in (ARI),
    a moment in it picked once - kept for acme_due."""
    try:
        targets = acme_targets(store)
    except Exception:                                   # noqa: BLE001
        return
    a = None
    try:
        for t, _name in targets:
            prof = tls_profile(store, t) or {}
            if prof.get('how') != 'ACME' or not prof.get('cert'):
                continue
            cid = ari_cert_id(prof['cert'])
            if not cid:
                continue
            if a is None:
                a = Acme(store)
                if not a.dir.get('renewalInfo'):
                    return                              # this CA has no ARI
            w = a.renewal_info(cid)
            if not w:
                continue
            fp = (prof.get('info') or {}).get('fingerprint') or ''
            was = _meta_json(store, 'acme:ari:' + t) or {}
            pick = was.get('pick') if (was.get('start'), was.get('end'), was.get('cert')) == \
                (w['start'], w['end'], fp) else None
            if not pick:
                pick = w['start'] + secrets.randbelow(max(1, int(w['end'] - w['start'])))
            store.set_meta('acme:ari:' + t, json.dumps(dict(w, pick=pick, at=time.time(), cert=fp)))
    except Exception as e:                              # noqa: BLE001
        log_sparing('acme-ari', 'ACME: the renewal window not asked: %s' % e, 'warn', every=6 * 3600)
    finally:
        if a:
            a.close()


def acme_tick(daemon):
    """Once an hour: what is due, ordered - in a thread of its own."""
    # In a thread (1.0.186): socket.getfqdn() waits on a DNS that does not
    # answer, and this is the main loop's.
    if time.time() - ACME_FQDN_SEEN['at'] >= 600:
        def pub():
            try:
                acme_host_publish(daemon.store)
            except Exception:                           # noqa: BLE001
                pass
        threading.Thread(target=pub, name='acme-acme-host', daemon=True).start()
    if CONFIG.get('acme') and time.time() - ACME_ARI['at'] >= ACME_ARI_EVERY and not ACME_WORK['busy']:
        ACME_ARI['at'] = time.time()
        def ari(store=daemon.store):
            with acme_dns_scope():      # the CA looked up as the orders look it up (1.0.205)
                acme_ari_refresh(store)
        threading.Thread(target=ari, name='acme-acme-ari', daemon=True).start()
    if not CONFIG.get('acme') or ACME_WORK['busy'] or \
            time.time() - ACME_WORK['at'] < ACME_EVERY:
        return
    ACME_WORK['at'] = time.time()
    store = daemon.store

    def look():
        # What is due worked out in a thread too (1.0.205): with no name given,
        # a node's own is socket.getfqdn(), which waits on a DNS that does not
        # answer - the main loop with it.
        try:
            due = [(t, n) for t, n in acme_targets(store) if acme_due(store, t, n)]
            if due and not ACME_WORK['busy']:
                acme_start(store, due, 'acme (renewal)')
        except Exception as e:                          # noqa: BLE001
            log_sparing('acme-due', 'ACME: what is due could not be looked at: %s' % e, 'warn',
                        every=3600)
    threading.Thread(target=look, name='acme-acme-due', daemon=True).start()


def acme_parallel_why(which):
    """Why these are ordered one after another, or '' when side by side
    (1.0.203). By hand, the page shows one TXT record at a time; acme-dns keeps
    the last two TXT records of its one subdomain for every name - a third
    order side by side would push one out."""
    if len(which) < 2 or ACME_PARALLEL < 2:
        return 'one'
    if (CONFIG.get('acme_challenge') or 'http-01') == 'dns-01':
        how = CONFIG.get('acme_dns') or 'manual'
        if how == 'manual':
            return 'by hand'
        if how == 'acmedns':
            return 'acme-dns'
    names = [n for _t, n in which]
    if len(set(names)) != len(names):
        return 'the same name twice'
    return ''


def acme_start(store, which, by):
    with _ACME_LOCK:
        if ACME_WORK['busy']:
            raise ValueError('a certificate is being ordered already')
        ACME_WORK.update(busy=True, says='starting', target='', n=0, of=len(which), done=0, each={})

    def one(t, n, i):
        # Each in a thread of its own: its names looked up by ACME's DNS
        # servers, its words on its own card.
        _ACME_DNS.on = True
        _ACME_CUR.target = t
        with _ACME_LOCK:
            ACME_WORK['each'][t] = {'says': 'starting', 'at': time.time(), 'n': i + 1}
            ACME_WORK.update(target=t, n=max(ACME_WORK['n'], i + 1))
        lease = 'acme:busy:%s' % t
        try:
            # One node orders a certificate at a time (1.0.209): ordered from the
            # other node's pages while this one renewed it, both spent the CA's
            # limit and the last one saved won. Held half an hour at most.
            try:
                held = json.loads(store.get_meta(lease) or '{}')
            except ValueError:
                held = {}
            if held.get('node') and held['node'] != node_name() and \
                    float(held.get('until') or 0) > time.time():
                log('ACME: %s is being ordered on %s already - not ordered here too'
                    % (n, held['node']), 'warn')
                return
            store.set_meta(lease, json.dumps({'node': node_name(), 'until': time.time() + 1800}))
            acme_order(store, t, n, by, acme_progress)
        except AcmeError as e:
            log('ACME: %s' % e, 'warn')
        except Exception as e:                          # noqa: BLE001
            # Never the others with it: one order gone wrong is said, the rest go on.
            log('ACME: the order for %s stopped: %s' % (n, e), 'error')
        finally:
            try:
                if json.loads(store.get_meta(lease) or '{}').get('node') == node_name():
                    store.db.run('DELETE FROM meta WHERE k = ?', (lease,))
            except Exception:                           # noqa: BLE001
                pass
            with _ACME_LOCK:
                ACME_WORK['each'].pop(t, None)
                ACME_WORK['done'] += 1
            _ACME_CUR.target = ''

    def go():
        _ACME_DNS.on = True
        try:
            why = acme_parallel_why(which)
            if not why:
                # The account first, once (1.0.203): orders side by side, each
                # finding none (a new kind of its key, one the CA forgot), would
                # make an account each.
                try:
                    a = Acme(store)
                    a.close()
                except Exception as e:                  # noqa: BLE001
                    why = 'the account not ready (%s)' % str(e)[:120]
            if why:
                for i, (t, n) in enumerate(which):
                    one(t, n, i)
                return
            gate = threading.Semaphore(ACME_PARALLEL)
            threads = []

            def gated(t, n, i):
                with gate:
                    one(t, n, i)
            for i, (t, n) in enumerate(which):
                th = threading.Thread(target=gated, args=(t, n, i), name='acme-acme-%s' % t, daemon=True)
                th.start()
                threads.append(th)
            for th in threads:
                th.join()
        finally:
            with _ACME_LOCK:
                ACME_WORK.update(busy=False, says='', target='', n=0, of=0, done=0, each={})
    threading.Thread(target=go, name='acme-acme', daemon=True).start()


def acme_challenge(store, token):
    """The answer for the CA, or None: what acme.php gives on port 80."""
    if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', str(token or '')):
        return None
    got = _meta_json(store, 'acme:chal:' + token) or {}
    if not got.get('auth') or time.time() - float(got.get('at') or 0) > 3600:
        return None
    return got['auth']


def acme_file(store, host, path):
    """A commercial CA's DCV file (/.well-known/pki-validation/...) for host, or
    None: what acme.php gives on port 80 (acmelib/certs/runtime.http_file_put)."""
    import hashlib
    host = str(host or '').strip().lower().rstrip('.').split(':')[0]
    path = str(path or '')
    if not re.match(r'^[a-z0-9_.-]{1,253}\Z', host) or \
            not re.match(r'^/\.well-known/pki-validation/[A-Za-z0-9_.-]{1,128}\Z', path):
        return None
    k = 'acme:file:' + hashlib.sha256(('%s|%s' % (host, path)).encode('utf-8')).hexdigest()[:48]
    got = _meta_json(store, k) or {}
    if not isinstance(got.get('content'), str) or time.time() > float(got.get('until') or 0):
        return None
    return got['content']


def acme_work_view():
    """What is being ordered, copied under the lock: the orders side by side
    change it while it is read."""
    with _ACME_LOCK:
        out = dict(ACME_WORK)
        out['each'] = {t: dict(v) for t, v in ACME_WORK['each'].items()}
    return out


def acme_view(store):
    out = []
    for t in tls_targets(store):
        if t == 'vip' and not vip_conf(store).get('on'):
            continue
        prof = tls_profile(store, t) or {}
        info = prof.get('info') or {}
        out.append({'target': t, 'name': acme_name_of(store, t), 'state': acme_state(store, t),
                    'how': prof.get('how') or '', 'subject': info.get('subject'),
                    'issuer': info.get('issuer'), 'not_after': info.get('not_after'),
                    'keys': ' + '.join(x for x in [info.get('key') or '',
                                                   ((tls_alt(prof) or {}).get('info') or {}).get('key') or '']
                                       if x),
                    'care': acme_care(store, t), 'wanted': t in acme_wanted(store),
                    'before': acme_before(store, t),
                    'named': bool(str(store.settings_saved().get('acme_node_name@' + t) or '')
                                  .strip()) if t != 'vip' else bool(vip_conf(store).get('fqdn'))})
    mine = [t for t, _ in acme_targets(store)]
    acc = _meta_json(store, 'acme:account') or {}
    return {'on': bool(CONFIG.get('acme')), 'targets': out, 'mine': mine,
            'directory': acme_directory_url(), 'account': {
                'kid': acc.get('kid'), 'email': acc.get('email'), 'at': acc.get('at'),
                'key': ACME_KEY_WORDS.get(acc.get('kind') or 'ec', '') if acc.get('kid') else ''},
            'work': acme_work_view(), 'node': node_name(),
            'challenge': CONFIG.get('acme_challenge') or 'http-01',
            'dns_guide': acme_dns_guide(store),
            'manual': {k: v for k, v in (_meta_json(store, 'acme:manual') or {}).items()
                       if k in ('rr', 'txt', 'at', 'done')} or None}


def acme_reach_probe(store, target):
    """Whether http://NAME/.well-known/acme-challenge/ reaches an acme node that
    answers - asked from here, straight, as the CA will (from outside it may
    still be blocked: a firewall in front sees only what reaches it)."""
    name = acme_name_of(store, target) if target else ''
    if not name:
        raise ValueError('which certificate? its name is not known')
    token = 'acme-probe-' + secrets.token_urlsafe(16)
    want = token + '.' + secrets.token_urlsafe(8)
    store.set_meta('acme:chal:' + token, json.dumps({'auth': want, 'at': time.time(),
                                                    'name': name, 'probe': True}))
    url = 'http://%s/.well-known/acme-challenge/%s' % (name, token)
    began = time.time()
    out = {'name': name, 'url': url, 'ok': False}
    scope = acme_dns_scope()
    scope.__enter__()
    try:
        time.sleep(float(os.environ.get('ACME_ACME_SETTLE') or 3))
        req = urllib.request.Request(url, headers={'User-Agent': 'acme/%s (acme probe)' % __version__})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=10) as r:
            body = r.read(4096).decode('utf-8', 'replace').strip()
        out.update(ok=body == want, status=r.status,
                   said='answered as the CA wants it' if body == want else
                   'something answers on port 80, but not acme\'s answer: %r' % body[:80])
    except urllib.error.HTTPError as e:
        out['said'] = 'port 80 answers %d - nginx does not send /.well-known/acme-challenge/ to acme' % e.code
    except (OSError, ValueError) as e:
        out['said'] = 'port 80 of %s cannot be reached: %s' % (name, getattr(e, 'reason', e))
    finally:
        scope.__exit__()
        store.db.run('DELETE FROM meta WHERE k = ?', ('acme:chal:' + token,))
    out['ms'] = int((time.time() - began) * 1000)
    return out


def acme_http_names(store):
    """The names this node's port 80 answers the CA for."""
    want = CONFIG.get('acme_for') or 'vip'
    vip_on = bool(vip_conf(store).get('on'))
    out = []
    if want in ('vip', 'both') and vip_on:
        out.append(acme_name_of(store, 'vip'))
    if want in ('node', 'both') or (want == 'vip' and not vip_on):
        out.append(acme_name_of(store, node_name()))
    return [n for n in out if n and re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', n)]


