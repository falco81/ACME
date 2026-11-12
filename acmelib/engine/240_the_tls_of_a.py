# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the TLS of a target, kept ---------------------------------------------------------
def tls_targets(store):
    names = sorted(set([node_name()] + [n['name'] for n in ha_nodes(store)]))
    return names + ['vip']


def tls_save(store, target, prof, by):
    prof = dict(prof)
    prof['at'] = time.time()
    prof['by'] = by
    store.set_meta('web:tls:' + target, json.dumps(prof))


def tls_view(prof):
    """A profile as the pages may see it: no key."""
    if not prof:
        return None
    out = {k: v for k, v in prof.items() if k not in ('key', 'pending_key', 'alt')}
    out['has_key'] = bool(prof.get('key'))
    alt = tls_alt(prof)
    if alt:
        # The second certificate (1.0.196): what it is, never its key.
        out['alt'] = {'info': alt.get('info') or {}}
    out['pending'] = bool(prof.get('pending_key'))
    return out


def tls_policy_checked(b):
    preset = str(b.get('preset') or 'standard')
    if preset not in list(TLS_PRESETS) + ['custom']:
        raise ValueError('the TLS settings are standard, intermediate, modern or custom')
    out = {'preset': preset}
    if preset == 'custom':
        prot = b.get('protocols') or []
        if not isinstance(prot, list) or not prot or \
                any(p not in ('TLSv1.2', 'TLSv1.3') for p in prot):
            raise ValueError('the protocols are TLSv1.2 and/or TLSv1.3')
        out['protocols'] = [p for p in ('TLSv1.2', 'TLSv1.3') if p in prot]
        ciphers = str(b.get('ciphers') or '').strip()
        if ciphers:
            if not re.match(r'^(?!-)[A-Za-z0-9_+!@=:.-]{1,2000}\Z', ciphers):
                raise ValueError('the ciphers are an OpenSSL cipher list')
            _openssl(['ciphers', ciphers], what='OpenSSL does not know that cipher list')
        out['ciphers'] = ciphers
    dh = str(b.get('dh') or 'none')
    if dh not in DH_WORDS:
        raise ValueError('the DH parameters are one of %s' % ', '.join(DH_WORDS))
    out['dh'] = dh
    out['prefer'] = bool(b.get('prefer'))
    try:
        # Not said is the two years nginx is shipped with (1.0.94), not none:
        # the first TLS change on the pages dropped HSTS without a word.
        hv = b.get('hsts')
        out['hsts'] = max(0, min(63072000, int(hv) if hv not in (None, '') else 63072000))
    except (TypeError, ValueError):
        raise ValueError('HSTS is a number of seconds')
    hisec_tls(out)                          # 1.0.168
    return out


def tls_alt_for(cert):
    """What ties the ECDSA certificate to its RSA one (1.0.196): a certificate put
    in another way - uploaded, self-signed - leaves the second one out."""
    first = PEM_CERT.search(str(cert or ''))
    return hashlib.sha256((first.group(0) if first else str(cert or '')).strip().encode()).hexdigest()[:32]


def tls_alt(prof):
    a = (prof or {}).get('alt') or {}
    if a.get('cert') and a.get('key') and (prof or {}).get('cert') and \
            a.get('for') == tls_alt_for(prof['cert']):
        return a
    return None


def tls_resolved(prof):
    """What root is handed for a profile: the parts and the lines."""
    if not prof:
        return None
    preset = prof.get('preset') or 'standard'
    p = TLS_PRESETS.get(preset) or {'protocols': prof.get('protocols') or ['TLSv1.2', 'TLSv1.3'],
                                    'ciphers': prof.get('ciphers') or ''}
    out = {'protocols': p['protocols'], 'ciphers': p['ciphers'], 'prefer': bool(prof.get('prefer')),
           'dh': prof.get('dh') or 'none',
           'hsts': int(prof['hsts']) if prof.get('hsts') not in (None, '') else 63072000}
    if prof.get('cert') and prof.get('key'):
        out.update(cert=prof['cert'], chain=prof.get('chain') or '', root=prof.get('root') or '',
                   key=unseal_secret(prof['key'], 'web:tls'))
        # A second certificate of the same names (1.0.196, ACME's "both"): ECDSA
        # beside the RSA one - nginx gives each client the one it takes.
        alt = tls_alt(prof)
        if alt:
            out['alt'] = {'cert': alt['cert'], 'chain': alt.get('chain') or '',
                          'key': unseal_secret(alt['key'], 'web:tls')}
    return out


# ---- what this node asks of root, and how it went -------------------------------------
def vip_plain(addr, like=''):
    """An address as keepalived takes it: itself, or a host name's first address
    of the VIP's family (1.0.209); '' when there is none."""
    addr = str(addr or '').strip()
    if not addr:
        return ''
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        pass
    want = (_fam(like) if like else 0) or 4
    for a in addresses_cached(addr):
        try:
            if ipaddress.ip_address(a.split('%')[0]).version == want:
                return a.split('%')[0]
        except ValueError:
            continue
    return ''


def vip_peer_seen(store):
    """The other node's address as its heartbeat says, when ha_peer is not set
    (a cluster of one shared database)."""
    me = node_name()
    for n in ha_nodes(store):
        if n['name'] != me and n.get('address') and dbguard_node_ok(store, n['name']):
            return n['address']
    return ''


def _ip_fam(addr):
    """4 or 6 for an address (no prefix), 0 for anything else."""
    try:
        return ipaddress.ip_address(str(addr or '').split('%')[0]).version
    except ValueError:
        return 0


VIP_PUBLISHED_S = 600           # the other node's published network: this fresh, or not taken


def vip_peer_published(store, like):
    """The other node's ha_address as it publishes it in 'net:now:NAME' (1.0.56), as an
    address of the VIP's family - '' when there is none fresh. Only with one shared database:
    there ha_peer is written once, at the join, and after the other node's address changed
    keepalived kept unicasting to the old one - both nodes could hold the VIP address. A
    replicated pair has ha_peer moved by ha_readdress; a node that publishes no ha_address
    keeps ha_peer."""
    if CONFIG.get('ha_mode') == 'replicated':
        return ''
    me = node_name()
    for n in ha_nodes(store):
        if n['name'] == me:
            continue
        row = _meta_obj(store, 'net:now:' + n['name'])
        try:
            fresh = abs(time.time() - float(row.get('at') or 0)) < VIP_PUBLISHED_S
        except (TypeError, ValueError):
            fresh = False
        got = vip_plain(row.get('ha_address'), like) if fresh else ''
        if got and _ip_fam(got) == (_fam(like) or 4):
            return got
    return ''


def vip_family_fix(store, like, own, peer):
    """(own, peer) of the VIP address's family (1.0.56): an address of the other family (an
    IPv6 cluster with an IPv4 VIP address, or the other way round) made root refuse the whole
    web request, for good. This machine's own address of that family is taken - the other
    node's from ha_peer, its heartbeat or the live addresses it publishes - those in the VIP
    address's subnet first; '' when there is none (the VIP waits), never a mismatched pair."""
    fam = _fam(like)
    if not fam:
        return own, peer
    try:
        net = ipaddress.ip_interface(str(like)).network
    except ValueError:
        net = None
    v = vip_conf(store)
    skip = set()
    for a in (v.get('address'), v.get('address6')):
        try:
            skip.add(str(ipaddress.ip_interface(str(a)).ip))
        except ValueError:
            pass

    def pick(cands, also_skip=()):
        good = []
        for a in cands:
            a = str(a or '').strip().split('/')[0].split('%')[0]
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                continue
            if ip.version != fam or ip.is_loopback or ip.is_link_local or ip.is_unspecified or \
                    str(ip) in skip or str(ip) in also_skip or str(ip) in good:
                continue
            good.append(str(ip))
        inside = [a for a in good if net is not None and ipaddress.ip_address(a) in net]
        return (inside or good or [''])[0]
    if peer and _ip_fam(peer) != fam:
        me = node_name()
        cands = [vip_plain(CONFIG.get('ha_peer'), like)]
        for n in ha_nodes(store):
            if n['name'] == me:
                continue
            if n.get('address') and dbguard_node_ok(store, n['name']):
                cands.append(vip_plain(n['address'], like))
            live = (_meta_obj(store, 'net:now:' + n['name']).get('data') or {}).get('live') or {}
            for k in ('addrs4', 'addrs6'):
                cands += [x.get('addr') for x in live.get(k) or [] if isinstance(x, dict)]
        peer = pick(cands)
    if own and _ip_fam(own) != fam:
        own = pick(sorted(local_addresses()), (peer,))
    return own, peer


VIP_LAST_FILE = STATE_DIR / 'vip-last.json'


def vip_last(address):
    """This node's and the other node's address as last told keepalived for this VIP address."""
    try:
        got = json.loads(VIP_LAST_FILE.read_text())
    except (OSError, ValueError):
        return None
    if isinstance(got, dict) and got.get('address') == address and got.get('own') and got.get('peer'):
        return got
    return None


def vip_last_keep(address, own, peer):
    was = vip_last(address)
    if was and was.get('own') == own and was.get('peer') == peer:
        return
    try:
        write_replacing(VIP_LAST_FILE, json.dumps({'address': address, 'own': own, 'peer': peer,
                                                   'at': time.time()}), 0o640)
    except OSError:
        pass


SAVED_KEYS = {'at': 0.0, 'keys': frozenset()}


def saved_keys(store):
    """The names of the settings saved in the database - read at most every 30 s (otp 1.0.239):
    the web state is worked out every few seconds, and "was it ever switched on" (behind a
    balancer, signed in by it) asked the database each time, twice."""
    t = time.time()
    if t - SAVED_KEYS['at'] > 30 or t < SAVED_KEYS['at']:
        SAVED_KEYS['keys'] = frozenset(store.settings_saved())
        SAVED_KEYS['at'] = t
    return SAVED_KEYS['keys']


def realip_desired(store):
    """{'from': [...], 'header', 'recursive'} for nginx - empty 'from' takes acme's own out
    again; None where it was never switched on (nginx left as it is)."""
    if CONFIG.get('web_proxy'):
        nets = []
        for w in re.split(r'[\s,;]+', str(CONFIG.get('web_proxy_from') or '')):
            if w:
                try:
                    nets.append(str(ipaddress.ip_network(w, strict=False)))
                except ValueError:
                    continue
        if nets:
            return {'from': nets, 'header': str(CONFIG.get('web_proxy_header') or 'X-Forwarded-For'),
                    'recursive': bool(CONFIG.get('web_proxy_recursive', 1))}
    try:
        # Switched off: the row kept off (otp 1.0.238) - or, switched off before that, the
        # balancers named are still there.
        if any(k.split('@', 1)[0].startswith('web_proxy') for k in saved_keys(store)):
            return {'from': [], 'header': '', 'recursive': False}
    except Exception:                                   # noqa: BLE001
        pass
    return None


def sso_peer_desired(store):
    """True: nginx tells the enrolment pages which machine a request came from (ACME_PEER);
    False: no longer; None where the sign-in by the balancer was never switched on (nginx as
    it is)."""
    if CONFIG.get('portal_sso'):
        return True
    try:
        if any(k.split('@', 1)[0].startswith('portal_sso') for k in saved_keys(store)):
            return False
    except Exception:                                   # noqa: BLE001
        pass
    return None


def web_desired(store):
    me = node_name()
    v = vip_conf(store)
    vip = {'on': False}
    many = bool(CONFIG.get('ha_mode'))
    if v.get('on') and many:
        vip = {'on': True, 'address': v.get('address'), 'fqdn': v.get('fqdn') or '',
               'address6': v.get('address6') or '',
               'vrid': int(v.get('vrid') or 51), 'auth': vip_auth(),
               'own': vip_plain(CONFIG.get('ha_address') or node_address(), v.get('address')),
               'peer': vip_plain(CONFIG.get('ha_peer') or vip_peer_seen(store), v.get('address')),
               'iface': (v.get('ifaces') or {}).get(me, '')}
        # One shared database (1.0.56): the other node's address as it publishes it now wins
        # over ha_peer, written once at the join - see vip_peer_published.
        published = vip_peer_published(store, v.get('address'))
        if published and published != vip['peer']:
            vip['peer'] = published
        vip['own'], vip['peer'] = vip_family_fix(store, v.get('address'), vip['own'], vip['peer'])
        last = vip_last(v.get('address'))
        if last and (_ip_fam(last.get('own')) != _ip_fam(last.get('peer')) or
                     _ip_fam(last.get('own')) != (_fam(v.get('address')) or 4)):
            last = None                 # a pair of the other family, remembered (1.0.56)
        if vip['own'] and vip['peer']:
            vip_last_keep(v.get('address'), vip['own'], vip['peer'])
        elif last:
            # The addresses last known kept (otp 1.0.234): a name not answered for a moment (DNS
            # away, or the other node's) switched the VIP address off on this node - keepalived
            # stopped, its file and nginx's server for it taken away.
            log_sparing('vip-addr', 'the VIP address goes on with the addresses last known: %s '
                        'cannot be told now (ha_address / ha_peer)' % (
                            'this node\'s' if not vip['own'] else 'the other node\'s'), 'warn',
                        every=3600)
            vip['own'] = vip['own'] or last['own']
            vip['peer'] = vip['peer'] or last['peer']
        if not vip['own'] or not vip['peer']:
            # Root takes addresses only (1.0.209): a host name - or no other node
            # named - refused the whole request, and no certificate, firewall rule
            # or access list reached nginx on this node again. The VIP waits.
            log_sparing('vip-addr', 'the VIP address waits: %s is not an address this node '
                        'can tell keepalived (ha_address / ha_peer)' % (
                            'this node' if not vip['own'] else 'the other node'), 'warn',
                        every=3600)
            vip = {'on': False}
    vip_tls = tls_profile(store, 'vip') if vip['on'] else None
    if vip_tls and vip_tls.get('cert') and not vip['fqdn']:
        # A certificate of the VIP address's own, its name taken away since (otp 1.0.242): root
        # refused the whole request for it, and no change of nginx, keepalived or the
        # firewall reached this node again - the VIP address stayed away. The node's
        # certificate serves the address until a name is given again.
        log_sparing('vip-noname', 'the VIP address has a certificate of its own but no name: '
                    'the node\'s certificate serves it until the name is given again (Settings - '
                    'TLS and the VIP address)', 'warn', every=3600)
        vip_tls = None
    tls = {'node': tls_resolved(tls_profile(store, me)), 'vip': tls_resolved(vip_tls)}
    out = {'node': me, 'vip': vip, 'tls': tls}
    # Asked only once set on the pages (1.0.52): a request from before had
    # neither, and its hash stays what it was.
    fw, access = fw_desired(store), access_desired(store)
    # Behind a balancer (otp 1.0.237): asked only once switched on, or switched off again after -
    # a request from before had none, and its hash stays what it was.
    rp = realip_desired(store)
    if rp is not None:
        out['realip'] = rp
    # Signed in by the balancer (otp 1.0.239): the same - asked once switched on, or off after.
    sp = sso_peer_desired(store)
    if sp is not None:
        out['sso_peer'] = sp
    if fw is not None:
        out['fw'] = fw
    if access is not None:
        out['access'] = access
    # ACME (1.0.169): port 80 answers the CA for the names ordered - the web
    # address's on every node, wherever it is now.
    if CONFIG.get('acme'):
        out['acme'] = acme_http_names(store)
    # The CRLs of acme's own authorities at /pki/ (port 80 and 443): asked
    # only while publishing is on, so a request from before keeps its hash.
    try:
        if int(CONFIG.get('pki_publish', 1) or 0):
            out['pki'] = True
    except (TypeError, ValueError):
        pass
    return out


def web_hash(desired):
    return hashlib.sha256(json.dumps(desired, sort_keys=True).encode()).hexdigest()


def web_status():
    try:
        fd = os.open(str(WEB_DIR / 'status.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(1 << 20).decode('utf-8'))
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


WEB_RETRY_S = int(os.environ.get('ACME_WEB_RETRY_S') or 900)


def web_tick(store):
    """Asks root for this node's part when what is wanted has changed."""
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    desired = web_desired(store)
    # Nothing ever asked and nothing to ask: no request at all.
    st = web_status()
    if not st and not desired['vip']['on'] and not desired['tls']['node'] and \
            'fw' not in desired and 'access' not in desired and 'acme' not in desired:
        return
    h = web_hash(desired)
    if st.get('state') == 'done':
        try:
            web_self_check(store, st)
        except Exception as e:                          # noqa: BLE001
            # never in the way of the rest (1.0.93): a name it could not send stopped every
            # request to root after it, at each tick
            log_sparing('web-selfcheck', 'checking what nginx sends: %s' % e, 'warn', every=3600)
    if st.get('hash') == h:
        if st.get('state') == 'done':
            # Done, by root's last word - and nginx really has it (1.0.104):
            # a machine put back from its own backup, nginx set up again or
            # a file changed by hand is given what the database says again.
            drift = web_drift(desired)
            if not drift or time.time() - WEB_DRIFT['at'] < 1800:
                return
            WEB_DRIFT['at'] = time.time()
            log('the web certificate in place is not the one wanted (%s): asked again' % drift,
                'warn')
            store.add_event('settings', 'the certificate nginx has on %s is not the one saved '
                            '(%s): put in again' % (node_name(), drift), 'warn')
        # Failed with exactly this: asked again only when somebody says so.
        # Or once after a restart (1.0.120): it may have failed on what the
        # machine did not have yet - its new address, say.
        # And every 15 minutes (1.0.187): a failure on something passing - a
        # mirror that did not answer while keepalived was installed - left the
        # VIP address and the certificates as they were until somebody looked.
        if float(store.get_meta('web:retry:' + node_name()) or 0) <= float(st.get('at') or 0):
            if st.get('state') != 'failed':
                return
            rebooted = not WEB_DRIFT.get('boot_retried') and boot_time() > float(st.get('at') or 0)
            if not rebooted and time.time() - float(st.get('at') or 0) < WEB_RETRY_S:
                return
            if rebooted:
                WEB_DRIFT['boot_retried'] = True
            log_sparing('web-retry', 'the web part failed (%s): asked again' % '; '.join(
                st.get('said') or [])[:200], 'warn', every=3000)
    # Root at work on it (1.0.59): while it holds request.taken the status
    # still has the old hash, and the same request was written again - every
    # change applied twice.
    taken = WEB_DIR / 'request.taken'
    if (taken.exists() and time.time() - taken.stat().st_mtime < 600) or (
            WEB_ASKED.get('hash') == h and time.time() - float(WEB_ASKED.get('at') or 0) < 600
            and float(st.get('at') or 0) < float(WEB_ASKED.get('at') or 0)):
        return
    req = WEB_DIR / 'request.json'
    if req.exists() and time.time() - req.stat().st_mtime < 600:
        # Waiting for root: left as it is when it asks for this very thing,
        # replaced when what is wanted changed meanwhile.
        try:
            if json.loads(req.read_text()).get('hash') == h:
                return
        except (OSError, ValueError):
            return
    body = dict(desired, id=secrets.token_hex(8), hash=h)
    tmp = WEB_DIR / 'request.part'
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(body, f)
    os.replace(str(tmp), str(req))
    WEB_ASKED['hash'] = h
    WEB_ASKED['at'] = time.time()


WEB_SELF_PORT = int(os.environ.get('ACME_WEB_SELF_PORT') or 443)


def web_self_check(store, st):
    """After nginx was given its part (1.0.89): acme connects to it as a client that fetches
    nothing (curl, the other applications) - the system's roots, plus the root kept with a
    private certificate - and says whether the chain it is sent is enough. Once for each
    time root applied it; a refusal is an event, not silence."""
    at = float(st.get('at') or 0)
    key = 'web:selfcheck:' + node_name()
    try:
        had = json.loads(store.get_meta(key) or '{}')
    except ValueError:
        had = {}
    if not at or float(had.get('applied') or 0) >= at:
        # ...and the VIP address that moved here since (keepalived), checked again
        try:
            v = vip_conf(store)
            here = bool(v.get('on') and vip_here(v.get('address')))
        except Exception:                               # noqa: BLE001
            here = WEB_SELF_VIP['here']
        if here != WEB_SELF_VIP['here']:
            web_self_check_vip(store, at)
        return had
    prof = tls_profile(store, node_name()) or {}
    info = prof.get('info') or {}
    if not prof.get('cert') or info.get('self_signed'):
        got = {'ok': None, 'words': 'self-signed or none - not checked'}
    else:
        got = web_self_connect(prof)
    got.update(applied=at, at=time.time())
    store.set_meta(key, json.dumps(got))
    if got.get('ok') is False:
        store.add_event('settings', 'a client that fetches nothing (curl, the other '
                        'applications) refuses what nginx sends on %s: %s' % (
                            node_name(), got.get('why') or ''), 'warn')
    # The VIP address (HA, keepalived): its own certificate, checked on the node that holds
    # the address - on that address, as the clients reach it.
    web_self_check_vip(store, at)
    return got


def web_self_check_vip(store, at):
    """The VIP address's certificate, checked on its address by the node holding it - when
    root applied it, and again when the address came here (1.0.93: after a failover the one
    shown was another node's, or one from an older certificate). A node without it says
    nothing."""
    v = vip_conf(store)
    vprof = tls_profile(store, 'vip') or {}
    vkey = 'web:selfcheck:vip:' + node_name()
    here = bool(v.get('on') and vip_here(v.get('address')))
    WEB_SELF_VIP['here'] = here
    if not here:
        if store.get_meta(vkey) is not None:
            store.db.run('DELETE FROM meta WHERE k = ?', (vkey,))
        return
    if vprof.get('cert'):
        if (vprof.get('info') or {}).get('self_signed'):
            vgot = {'ok': None, 'words': 'self-signed - not checked'}
        else:
            vgot = web_self_connect(vprof, host=vip_plain(str(v.get('address') or '').split('/')[0]))
        vgot.update(applied=at, at=time.time())
        store.set_meta(vkey, json.dumps(vgot))
        if vgot.get('ok') is False:
            store.add_event('settings', 'a client that fetches nothing (curl, the other '
                            'applications) refuses what nginx sends on the VIP address: %s'
                            % (vgot.get('why') or ''), 'warn')


WEB_SELF_VIP = {'here': None}


def web_self_connect(prof, port=None, host='127.0.0.1'):
    info = prof.get('info') or {}
    name = next((n for n in info.get('san') or [] if n and '*' not in n), '') or \
        info.get('cn') or ''
    ctx = ssl.create_default_context()
    ca = chain_ca_file()
    try:
        if ca:
            ctx.load_verify_locations(cafile=ca)
        if prof.get('root'):
            ctx.load_verify_locations(cadata=prof['root'])
    except (OSError, ssl.SSLError, ValueError):
        pass
    ctx.verify_flags &= ~getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
    ctx.check_hostname = False
    # a name nginx can be asked by (1.0.93): a CN that is no host name - a label over 63
    # characters, spaces - made the handshake raise, and nothing after it ran
    sni = name if name and re.match(r'^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}'
                                    r'[A-Za-z0-9])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}'
                                    r'[A-Za-z0-9])?\.?$', name) else None
    try:
        with socket.create_connection((host or '127.0.0.1', port or WEB_SELF_PORT),
                                      timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                pass
        return {'ok': True, 'words': 'checked as a client that fetches nothing: the whole chain '
                                     'is sent'}
    except ssl.SSLCertVerificationError as e:
        why = str(getattr(e, 'verify_message', '') or e)
        return {'ok': False, 'why': why, 'words': 'a client that fetches nothing (curl, the '
                                                  'other applications) refuses what nginx '
                                                  'sends: %s' % why}
    except Exception as e:                              # noqa: BLE001
        return {'ok': None, 'words': 'what nginx sends could not be checked: %s' % e}


WEB_ASKED = {'hash': '', 'at': 0.0}
WEB_DRIFT = {'at': 0.0}
# The folder root writes them into (1.0.56): ACME_VIP_CERT_DIR moves it (two nodes on one
# machine) - read from the fixed /etc/nginx/certs, the check compared another installation's
# certificate and said "not the one saved" after every certificate made again.
_NGINX_CERT_DIR = os.environ.get('ACME_VIP_CERT_DIR') or '/etc/nginx/certs'
NGINX_CERT_FILES = {'node': os.path.join(_NGINX_CERT_DIR, 'acme.pem'),
                    'vip': os.path.join(_NGINX_CERT_DIR, 'acme-vip.pem')}


def _first_pem(text):
    m = PEM_CERT.search(text or '')
    return re.sub(r'\s+', '', m.group(0)) if m else ''


def web_drift(desired):
    """Why the certificates nginx has are not the ones wanted - '' when they
    are, or when that cannot be told (a file not readable here)."""
    for target in ('node', 'vip'):
        t = (desired.get('tls') or {}).get(target)
        if not t or not t.get('cert'):
            continue
        path = NGINX_CERT_FILES[target]
        try:
            with open(path) as f:
                have = _first_pem(f.read(200000))
        except FileNotFoundError:
            return '%s is not there' % path
        except OSError:
            continue
        if have and have != _first_pem(t['cert']):
            return '%s holds another certificate' % path
    return ''


def web_progress():
    """What root is doing now, if anything (1.0.50)."""
    try:
        fd = os.open(str(WEB_DIR / 'progress.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(65536).decode('utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(got, dict) or time.time() - float(got.get('at') or 0) > 3 * 3600:
        return None
    got['now'] = time.time()
    return got


def web_state(store):
    """This node's web side, for its heartbeat: what root said last, whether
    that is what is wanted now, and the address."""
    st = web_status()
    desired_hash = ''
    try:
        desired_hash = web_hash(web_desired(store))
    except Exception:                                   # noqa: BLE001
        pass
    role = ''
    try:
        role = VIP_ROLE.read_text().split()[0]
    except (OSError, IndexError):
        pass
    v = vip_conf(store)
    # The files root writes and web_drift reads (1.0.56), not always /etc/nginx/certs.
    return {'cert_now': cert_now(NGINX_CERT_FILES['node']),
            'vip_cert_now': cert_now(NGINX_CERT_FILES['vip']),
            'self_check': _json_meta(store, 'web:selfcheck:' + node_name()),
            'vip_self_check': _json_meta(store, 'web:selfcheck:vip:' + node_name()),
            'state': st.get('state') or '', 'said': (st.get('said') or [])[-6:],
            'at': st.get('at'), 'current': bool(st) and st.get('hash') == desired_hash,
            'waiting': (WEB_DIR / 'request.json').exists(),
            'progress': web_progress(),
            'iface': (st.get('applied') or {}).get('iface') or '',
            'vip_here': vip_here(v.get('address')) if v.get('on') else False,
            'role': role, 'health': dict(VIP_HEALTH),
            'fw': dict(st.get('fw') or {}, **fw_now_read()), 'access': st.get('access') or {},
            'ifaces': sorted(os.listdir('/sys/class/net')) if os.path.isdir('/sys/class/net')
            else []}


def fw_now_read():
    """The whole firewall as root last read it (1.0.67): {'full': {4, 6},
    'full_at'}."""
    try:
        fd = os.open(str(WEB_DIR / 'fwnow.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(4 << 20).decode('utf-8'))
        full = got.get('full') or {}
        return {'full': {str(k): [str(x)[:400] for x in (v or [])][:1500] for k, v in full.items()},
                'full_at': got.get('at'), 'full_backend': got.get('backend')}
    except (OSError, ValueError, AttributeError):
        return {}


def fw_now_ask(wait=6.0):
    """Root asked to read the firewall again, and waited for (1.0.67)."""
    if not WEB_DIR.is_dir():
        return False
    t0 = time.time()
    try:
        (WEB_DIR / 'fw.ask').write_text(json.dumps({'at': t0}))
    except OSError:
        return False
    while time.time() - t0 < wait:
        if float(fw_now_read().get('full_at') or 0) >= t0:
            return True
        time.sleep(0.3)
    return False


CERT_NOW = {}


def cert_now(path):
    """What the certificate nginx has in `path` says - read again only
    when the file changes."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    had = CERT_NOW.get(path)
    if had and had[0] == (st.st_mtime, st.st_size):
        return had[1]
    try:
        with open(path) as f:
            text = f.read(200000)
        m = PEM_CERT.search(text)
        info = cert_info(m.group(0)) if m else None
        if info:
            all_ = PEM_CERT.findall(text)
            info['chain'] = max(0, len(all_) - 1)
            # What nginx sends, checked as curl and the other applications check it (1.0.89):
            # the system's roots, nothing fetched.
            if not info.get('self_signed'):
                ok, why = chain_verify(all_[0] + '\n', ''.join(c + '\n' for c in all_[1:]))
                info['chain_ok'] = ok
                info['chain_why'] = '' if ok else why[:200]
    except (OSError, ValueError):
        return None             # not kept: read again next time (1.0.57)
    CERT_NOW[path] = ((st.st_mtime, st.st_size), info)
    return info


def local_addresses():
    """Every address on this machine's interfaces, read from the kernel.

    Not by binding to it (1.0.55): with net.ipv4.ip_nonlocal_bind on - which
    the VIP address turns on since 1.0.51, so nginx can listen on it - a bind
    succeeds for an address the machine does not hold, and both nodes said
    they had the VIP address."""
    out = set()
    try:
        # IPv4: the local table of the FIB, "/32 host LOCAL" under each address.
        last = None
        with open('/proc/net/fib_trie') as f:
            for line in f:
                m = re.match(r'^\s*\|--\s+([0-9.]+)\s*\Z', line)
                if m:
                    last = m.group(1)
                elif last and '/32 host LOCAL' in line:
                    out.add(last)
    except OSError:
        pass
    try:
        with open('/proc/net/if_inet6') as f:
            for line in f:
                h = line.split()[0]
                if len(h) == 32:
                    out.add(str(ipaddress.IPv6Address(int(h, 16))))     # ::1 too (1.0.59)
    except (OSError, ValueError, IndexError):
        pass
    if not out and shutil.which('ip'):
        got = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True)
        for m in re.finditer(r'\binet6?\s+([0-9a-fA-F:.]+)/', got.stdout or ''):
            out.add(str(ipaddress.ip_address(m.group(1))))
    return out


def vip_here(address):
    """Does this machine hold the address now? Its interfaces say so."""
    if VIP_HERE_BY_ROLE:
        # Tests (1.0.187): two nodes on one machine both see the address on lo;
        # keepalived's own word says which holds it.
        try:
            return VIP_ROLE.read_text().split()[0] == 'MASTER'
        except (OSError, IndexError):
            return False
    try:
        ip = ipaddress.ip_interface(str(address or '')).ip
    except ValueError:
        return False
    return str(ip) in local_addresses()


