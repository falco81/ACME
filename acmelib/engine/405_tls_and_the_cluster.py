# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- TLS and the cluster's VIP address (1.0.47) ------------------------------------
def web_unmapped(web, me):
    """A node's web state without the firewall's rules and the access lists for
    an account that only reads (1.0.205): /api/firewall keeps them from it as
    the map of the network, and /api/web, /api/ha gave them all the same."""
    if (me or {}).get('role') in ('fulladmin', 'certadmin') or not isinstance(web, dict):
        return web
    return {k: v for k, v in web.items() if k not in ('fw', 'access')}


def syslog_target_text(host, port, proto):
    """host:port/proto as a target is written - an IPv6 address in brackets
    (1.0.205): written bare, it was refused when saved, and TLS could be
    switched neither on nor off."""
    return '%s:%d/%s' % ('[%s]' % host if ':' in str(host) else host, int(port), proto)


@route('GET', '/api/web')
def _web(h):
    me = h.me()
    store = h.store
    nodes = []
    for n in ha_nodes(store):
        one = {k: n.get(k) for k in ('name', 'me', 'alive', 'address', 'version', 'maintenance',
                                     'age', 'host')}
        one['web'] = web_unmapped(web_state(store) if n['me'] else (n.get('web') or {}), me)
        nodes.append(one)
    if not any(x['me'] for x in nodes):
        nodes.insert(0, {'name': node_name(), 'me': True, 'alive': True,
                         'address': node_address(), 'web': web_unmapped(web_state(store), me)})
    v = vip_conf(store)
    holder = [x['name'] for x in nodes if (x.get('web') or {}).get('vip_here')]
    return {'node': node_name(), 'cluster': bool(CONFIG.get('ha_mode')), 'nodes': nodes,
            'vip': dict(v, prefer_now=vip_prefer(store, v) if CONFIG.get('ha_mode') else '',
                        holder=holder),
            'tls': {t: tls_view(tls_profile(store, t)) for t in tls_targets(store)},
            'acme': {'on': bool(CONFIG.get('acme')), 'care': {
                t: acme_care(store, t) and t in acme_wanted(store) for t in tls_targets(store)},
                     'state': {t: acme_state(store, t) for t in tls_targets(store)},
                     'before': {t: acme_before(store, t) for t in tls_targets(store)}},
            'presets': TLS_PRESETS, 'dh': DH_WORDS,
            'may': me.get('role') == 'fulladmin'}


@route('POST', '/api/web')
def _web_do(h):
    s = h.me('fulladmin')
    who = s['name']
    b = h.body()
    act = str(b.get('action') or '')
    store = h.store
    target = str(b.get('target') or '')
    if act.startswith('tls_'):
        if target not in tls_targets(store):
            raise ApiError(400, 'there is no node or address called %s' % target)
        prof = tls_profile(store, target) or {}
        words = 'the VIP address' if target == 'vip' else target
    if act in ('tls_upload', 'tls_selfsigned'):
        if act == 'tls_upload':
            pfx = b''
            if b.get('pfx'):
                try:
                    pfx = base64.b64decode(str(b['pfx']), validate=True)
                except (ValueError, binascii.Error):
                    raise ApiError(400, 'the PFX / PKCS#12 file did not arrive whole')
                if len(pfx) > 200000:
                    raise ApiError(400, 'that is far bigger than any certificate file')
            # A second PFX (otp 1.0.240): the ECDSA certificate beside the RSA one.
            pfx2 = b''
            if b.get('pfx2'):
                try:
                    pfx2 = base64.b64decode(str(b['pfx2']), validate=True)
                except (ValueError, binascii.Error):
                    raise ApiError(400, 'the second PFX / PKCS#12 file did not arrive whole')
                if len(pfx2) > 200000:
                    raise ApiError(400, 'that is far bigger than any certificate file')
            pending = unseal_secret(prof['pending_key'], 'web:tls') if prof.get('pending_key') \
                else ''
            got, got2 = cert_bundles(b.get('cert'), b.get('key'), b.get('chain'), b.get('root'), pfx,
                                     str(b.get('password') or ''), pending, pfx2,
                                     str(b.get('password2') or ''))
            how = 'uploaded'
        else:
            names = [x.strip() for x in re.split(r'[\s,;]+', str(b.get('names') or '')) if x.strip()]
            try:
                days = int(b.get('days')) if b.get('days') not in (None, '') else 825
            except (TypeError, ValueError):
                raise ApiError(400, 'the days are a number')
            if not 1 <= days <= 3650:
                # 1.0.93: 0 made 825 days, a negative one an openssl error
                raise ApiError(400, 'a self-signed certificate lasts 1 to 3650 days')
            key, crt = make_selfsigned(str(b.get('cn') or '').strip(), names,
                                       days, str(b.get('kind') or 'rsa2048'),
                                       org=str(b.get('org') or ''))
            got, got2 = cert_bundle(crt, key), None
            how = 'self-signed, made here'
        info = got['info']
        if info.get('not_after') and info['not_after'] < time.time():
            raise ApiError(400, 'this certificate ran out on %s' % stamp(info['not_after']))
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=seal_secret(got['key'], 'web:tls'), info=info,
                    chain_info=got['chain_info'], root_info=got['root_info'], chain_state=got.get('chain_state'),
                    verify=got['verify'], how=how)
        if got2:
            # Both of the same names (otp 1.0.240): the ECDSA one beside, as ACME's "both".
            prof['alt'] = {'cert': got2['cert'], 'chain': got2['chain'],
                           'key': seal_secret(got2['key'], 'web:tls'), 'info': got2['info'],
                           'for': tls_alt_for(got['cert'])}
        else:
            prof.pop('alt', None)
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        tls_save(store, target, prof, who)
        # One put in by hand is kept (1.0.170): ACME does not replace it at its
        # next renewal - Automatic certificates → Look after it gives it back.
        acme_care_set(store, target, False, who, 'a certificate was put in by hand')
        store.add_event('settings', '%s put a certificate in for %s: %s (until %s)%s' % (
            who, words, info.get('subject'), stamp(info.get('not_after')) if info.get('not_after') else '?',
            ' - with a second one beside it, %s' % (got2['info'].get('key') or 'ECDSA') if got2 else ''),
            'warn', who=who)
        return {'message': 'the certificate of %s is kept; the node%s put%s it in within a few '
                           'seconds' % (words, 's' if target == 'vip' else '',
                                        '' if target == 'vip' else 's'),
                'tls': tls_view(prof)}
    if act in ('tls_chain', 'tls_chain_add'):
        return tls_chain_act(store, target, prof, words, who, act, b)
    if act == 'tls_csr':
        names = [x.strip() for x in re.split(r'[\s,;]+', str(b.get('names') or '')) if x.strip()]
        key, csr = make_csr(str(b.get('cn') or '').strip(), names, str(b.get('kind') or 'rsa2048'),
                            org=str(b.get('org') or ''), unit=str(b.get('unit') or ''),
                            country=str(b.get('country') or ''), city=str(b.get('city') or ''))
        prof.update(pending_key=seal_secret(key, 'web:tls'), csr=csr,
                    csr_at=time.time(), csr_cn=str(b.get('cn') or ''))
        tls_save(store, target, prof, who)
        store.add_event('settings', '%s made a certificate request for %s (%s)'
                        % (who, words, b.get('cn')), who=who)
        return {'message': 'the request is made: give it to your certificate authority, then '
                           'upload what it sends back - the key waits here', 'csr': csr,
                'tls': tls_view(prof)}
    if act == 'tls_csr_drop':
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        tls_save(store, target, prof, who)
        return {'message': 'the request and its waiting key are gone', 'tls': tls_view(prof)}
    if act == 'tls_policy':
        prof.update(tls_policy_checked(b))
        tls_save(store, target, prof, who)
        store.add_event('settings', '%s changed the TLS settings of %s: %s, DH %s%s' % (
            who, words, prof['preset'], prof['dh'],
            ', HSTS %d s' % prof['hsts'] if prof.get('hsts') else ''), who=who)
        slow = prof['dh'] in ('gen3072', 'gen4096')
        return {'message': 'the TLS settings of %s are kept%s' % (
            words, '; making the DH parameters takes a while' if slow else ''),
                'tls': tls_view(prof)}
    if act == 'tls_forget':
        store.db.run('DELETE FROM meta WHERE k = ?', ('web:tls:' + target,))
        acme_care_set(store, target, False, who, 'acme lets its TLS go')
        store.add_event('settings', '%s: acme no longer looks after the TLS of %s (nginx keeps '
                        'what it has)' % (who, words), 'warn', who=who)
        return {'message': 'acme no longer looks after the TLS of %s; nginx keeps the files it '
                           'has' % words}
    if act == 'tls_export':
        # A certificate as a file, in the format asked for (1.0.191); with its
        # private key only locked with a passphrase, only by a full
        # administrator (this route's), and each time an event.
        kind = str(b.get('kind') or 'pem')
        if not prof.get('cert'):
            raise ApiError(404, 'no certificate is kept for %s' % words)
        try:
            which = str(b.get('which') or 'rsa')
            which = {'main': 'rsa', 'alt': 'ec'}.get(which, which)
            if which not in ('rsa', 'ec', 'both'):
                raise ValueError('which: rsa, ec or both')
            blob, ending = tls_export(prof, kind, str(b.get('passphrase') or ''), bool(b.get('legacy')),
                                      which)
        except ValueError as e:
            raise ApiError(400, str(e))
        name = (re.sub(r'[^A-Za-z0-9._-]', '_', (prof.get('info') or {}).get('cn') or '') or
                ('web-address' if target == 'vip' else target)) + \
            {'rsa': '', 'ec': '-ecdsa', 'both': '-rsa-ecdsa'}[which] + ending
        words = words + {'rsa': '', 'ec': ' (the second, ECDSA one)',
                         'both': ' (both: RSA and ECDSA)'}[which]
        if TLS_EXPORT_KINDS[kind][2]:
            store.add_event('settings', '%s downloaded the certificate of %s WITH ITS PRIVATE KEY (%s, '
                            'locked with a passphrase)' % (who, words, TLS_EXPORT_KINDS[kind][0]),
                            'warn', who=who)
        else:
            store.add_event('settings', '%s downloaded the certificate of %s (%s)'
                            % (who, words, TLS_EXPORT_KINDS[kind][0]), who=who)
        return {'name': name, 'file': base64.b64encode(blob).decode(),
                'type': 'application/zip' if ending == '.zip' else
                'application/x-pkcs12' if kind == 'pfx' else 'application/octet-stream'}
    if act == 'tls_pem':
        if not prof.get('cert'):
            raise ApiError(404, 'no certificate is kept for %s' % words)
        return {'pem': prof['cert'] + (prof.get('chain') or ''), 'csr': prof.get('csr') or ''}
    if act in ('vip_save', 'vip_on', 'vip_off', 'vip_move'):
        if not CONFIG.get('ha_mode'):
            raise ApiError(409, 'the VIP address is for a cluster: make this node one of two '
                                'first (Settings - High availability)')
    if act == 'vip_save':
        v = vip_set(store, who, **vip_checked(b, store))
        store.add_event('settings', '%s set the VIP address: %s%s, VRRP id %d' % (
            who, v['address'], ' (%s)' % v['fqdn'] if v['fqdn'] else '', v['vrid']), who=who)
        return {'message': 'the VIP address is kept%s' % (
            '; each node puts it in within a few seconds' if v.get('on') else
            ' - turn it on when ready')}
    if act == 'vip_on':
        v = vip_conf(store)
        if not v.get('address'):
            raise ApiError(400, 'give the address first')
        vip_set(store, who, on=True)
        store.add_event('settings', '%s turned the VIP address %s on' % (who, v['address']),
                        'warn', who=who)
        return {'message': 'the VIP address is on: each node installs keepalived if it has to '
                           'and the address comes up on %s' % vip_prefer(store)}
    if act == 'vip_off':
        vip_set(store, who, on=False)
        store.add_event('settings', '%s turned the VIP address off' % who, 'warn', who=who)
        return {'message': 'the VIP address is off: keepalived stops on both nodes'}
    if act == 'vip_mode':
        mode = str(b.get('mode') or '')
        if mode not in ('back', 'stays'):
            raise ApiError(400, 'back or stays')
        changes = {'mode': mode}
        if mode == 'back':
            to = str(b.get('prefer') or '')
            if to and to not in {n['name'] for n in ha_nodes(store)}:
                raise ApiError(400, 'there is no node called %s' % to)
            if to:
                changes['prefer'] = to
        vip_set(store, who, **changes)
        v = vip_conf(store)
        store.add_event('settings', '%s: the VIP address %s' % (who, (
            'always goes back to %s' % vip_prefer(store, v)) if mode == 'back' else
            'stays where it is - it moves only when that node fails or by hand'), 'warn',
            who=who)
        return {'message': 'kept'}
    if act == 'vip_move':
        to = str(b.get('to') or '')
        nodes = {n['name']: n for n in ha_nodes(store)}
        if to not in nodes:
            raise ApiError(400, 'there is no node called %s' % to)
        if not nodes[to].get('alive'):
            raise ApiError(409, '%s is not answering: the address cannot go there' % to)
        if vip_conf(store).get('mode') == 'stays':
            vip_set(store, who, move_to=to, move_at=time.time())
            store.add_event('settings', '%s moved the VIP address to %s (it stays there)'
                            % (who, to), 'warn', who=who)
            return {'message': 'the VIP address goes to %s within a few seconds and stays '
                               'there' % to}
        vip_set(store, who, prefer=to)
        store.add_event('settings', '%s moved the VIP address to %s' % (who, to), 'warn', who=who)
        return {'message': 'the VIP address goes to %s within a few seconds (if it is healthy)'
                           % to}
    if act == 'retry':
        node = str(b.get('node') or node_name())
        if node not in {n['name'] for n in ha_nodes(store)} | {node_name()}:
            raise ApiError(400, 'there is no node called %s' % node)
        store.set_meta('web:retry:' + node, str(time.time()))
        return {'message': '%s tries again within a few seconds' % node}
    raise ApiError(400, 'no such thing to do')


def tls_chain_act(store, target, prof, words, who, act, b):
    """Complete the chain (1.0.89): the certificate kept, checked again against the system's
    roots and completed from its CA Issuers addresses - nginx then sends the whole chain. Or
    the missing authority by hand, when it cannot be fetched (no CA Issuers address, no way
    out, a private CA): only certificates of authorities, never a key; a root goes beside the
    chain (kept to check with, never sent), the rest into the chain in order. The answer has
    `complete`, not `ok` - an ok: false would read as an error without words."""
    if not prof.get('cert'):
        raise ApiError(404, 'no certificate is kept for %s' % words)
    leaf = prof['cert'].strip()
    if cert_info(leaf).get('self_signed'):
        raise ApiError(400, 'the certificate of %s is self-signed - it has no chain' % words)
    cur = [m.group(0) for m in PEM_CERT.finditer(prof.get('chain') or '')]
    roots = [m.group(0) for m in PEM_CERT.finditer(prof.get('root') or '')]
    added = []
    if act == 'tls_chain_add':
        text = str(b.get('text') or '')
        if len(text) > 262144:
            raise ApiError(400, 'that is far bigger than the certificates of a chain')
        if re.search(r'PRIVATE KEY', text):
            raise ApiError(400, 'only the certificates of the authorities - no private key')
        given = [m.group(0) for m in PEM_CERT.finditer(text)]
        if not given:
            raise ApiError(400, 'no certificate in it (-----BEGIN CERTIFICATE-----, or a .cer '
                                'file)')
        if len(given) > 8:
            raise ApiError(400, '%d certificates - the chain of one certificate is a few'
                           % len(given))
        try:
            infos = {c: cert_info(c) for c in given + cur + roots}
        except ValueError as e:
            raise ApiError(400, str(e))
        have = {infos[c].get('fingerprint') for c in cur + roots}
        have.add((prof.get('info') or {}).get('fingerprint'))
        new_roots, new_inter = [], []
        for c in given:
            if infos[c].get('fingerprint') in have:
                continue
            have.add(infos[c].get('fingerprint'))
            (new_roots if infos[c].get('self_signed') else new_inter).append(c)
        if not new_roots and not new_inter:
            raise ApiError(400, 'every certificate in it is there already')
        # In order from the certificate: each the issuer of the one before.
        pool = cur + new_inter
        ordered, at = [], cert_info(leaf)
        while pool:
            nxt = next((c for c in pool if infos[c].get('subject') == at.get('issuer')), None)
            if not nxt:
                break
            ordered.append(nxt)
            pool.remove(nxt)
            at = infos[nxt]
        added = [c for c in new_inter if c in ordered] or \
            [c for c in new_roots if infos[c].get('subject') == at.get('issuer')]
        if not added:
            raise ApiError(400, 'none of these is the authority that signed the chain\'s last '
                                'certificate (%s)' % _cn_of(at.get('issuer')))
        cur, roots = ordered, roots + new_roots
    root_now = ''.join(c.strip() + '\n' for c in roots)
    chain, state = chain_complete(leaf, cur, root_now)
    prof.update(chain=''.join(c + '\n' for c in chain),
                chain_info=[cert_info(c) for c in chain], root=root_now,
                root_info=[cert_info(c) for c in roots], chain_state=state)
    alt = prof.get('alt') if isinstance(prof.get('alt'), dict) else None
    if alt and alt.get('cert'):
        # The second certificate (ECDSA) of the same names: its chain completed too.
        acur = [m.group(0) for m in PEM_CERT.finditer(alt.get('chain') or '')]
        achain, ast = chain_complete(alt['cert'], acur, root_now)
        alt['chain'] = ''.join(c + '\n' for c in achain)
        alt['chain_state'] = ast        # its own (1.0.93): it was thrown away
        if ast.get('ok') is False and state.get('ok'):
            state = dict(state, words=state['words'] + ' - the ECDSA one beside it: '
                         + ast.get('words', ''))
    tls_save(store, target, prof, who)
    if act == 'tls_chain_add':
        store.add_event('settings', '%s added %s to the chain of the certificate of %s: %s' % (
            who, ', '.join(cert_info(c).get('cn') or '?' for c in added), words,
            state['words']), 'info' if state.get('ok') else 'warn', who=who)
    else:
        store.add_event('settings', '%s checked the chain of the certificate of %s: %s' % (
            who, words, state['words']), 'info' if state.get('ok') else 'warn', who=who)
    return {'message': state['words'], 'complete': bool(state.get('ok')),
            'tls': tls_view(prof)}

