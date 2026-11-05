# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- isemon over TLS (1.0.172) -----------------------------------------------------------
# Settings → isemon → Encrypted sending: the syslog lines to isemon over TLS
# (6514/tcp, rsyslog's gtls on the other side), isemon's certificate checked.
# Where isemon has none, acme's own authority (the one of the link between the
# databases and of the database's TLS) makes one for it, given away once as a
# locked ZIP with the rsyslog configuration that takes it. Mutual TLS: each node
# shows isemon a certificate of its own from the same authority - made and
# renewed by the node itself - so isemon takes lines from acme's nodes only.
ISEMON_CLIENT_DAYS = 825
ISEMON_CLIENT_RENEW_DAYS = 60
ISEMON_SERVER_DAYS = 1825
ISEMON_CLIENT_CRT = STATE_DIR / 'isemon-client.crt'
ISEMON_CLIENT_KEY = STATE_DIR / 'isemon-client.key'
ISEMON_TLS_WORK = {'at': 0.0, 'said': 0.0}


def isemon_tls_ctx():
    """The TLS context the shipper speaks to isemon with."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ca = str(CONFIG.get('isemon_ca') or '').strip()
    if ca:
        ctx.load_verify_locations(cadata=ca)
    if not CONFIG.get('isemon_verify', 1):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if CONFIG.get('isemon_mtls') and ISEMON_CLIENT_CRT.exists() and ISEMON_CLIENT_KEY.exists():
        ctx.load_cert_chain(str(ISEMON_CLIENT_CRT), str(ISEMON_CLIENT_KEY))
    return ctx


def _isemon_peer_names(store):
    """The names of the nodes as isemon's PermittedPeer lists them."""
    return [re.sub(r'[^A-Za-z0-9.-]', '', n)[:64] or 'acme'
            for n in sorted(set(host_nodes(store)))]


def _isemon_pair_ok():
    """Whether the key on disk is the one of the certificate beside it."""
    try:
        return _pub_of_key(ISEMON_CLIENT_KEY.read_text()).strip() == \
            _pub_of_cert(ISEMON_CLIENT_CRT.read_text()).strip()
    except (OSError, ValueError):
        return False


def isemon_client_cert(store, force=False):
    """This node's own certificate for isemon (mutual TLS): made from acme's
    authority, renewed 60 days before it ends, kept sealed in the database and
    as two files only acme reads. Returns its end."""
    k = 'isemon:client:' + node_name()
    got = _meta_obj(store, k)
    end = float(got.get('end') or 0)
    fresh = end - time.time() > ISEMON_CLIENT_RENEW_DAYS * 86400
    if not force and fresh and ISEMON_CLIENT_CRT.exists() and ISEMON_CLIENT_KEY.exists() and \
            _isemon_pair_ok():
        return end
    if not force and fresh and got.get('cert') and got.get('key'):
        key = unseal_secret(got['key'], bind=k)       # files gone: written again
        crt = got['cert']
    else:
        with HATLS_LOCK:
            ca = hatls_ca(store)
            if not ca['cas'] or float(ca['cas'][0].get('end') or 0) - time.time() < \
                    HATLS_CA_ROLL_DAYS * 86400:
                hatls_ca_make(store, 'acme (isemon)')
        name = re.sub(r'[^A-Za-z0-9.-]', '', node_name())[:64] or 'acme'
        key, crt = hatls_issue(store, [name], eku='clientAuth', days=ISEMON_CLIENT_DAYS, cn=name)
        end = _cert_end(crt)
        store.set_meta(k, json.dumps({'cert': crt, 'key': seal_secret(key, bind=k), 'end': end,
                                      'at': time.time()}))
        store.add_event('settings', 'a certificate of %s for isemon was made from acme\'s '
                        'authority, good until %s' % (node_name(), stamp(end)))
    # Both written beside first, then both put in (1.0.205): replaced one after
    # the other, a full disk between them left a key with another's certificate
    # - and the early return above kept it so for months.
    pairs = ((ISEMON_CLIENT_KEY, key, 0o600), (ISEMON_CLIENT_CRT, crt, 0o644))
    for path, text, mode in pairs:
        tmp = str(path) + '.new'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(text.strip() + '\n')
            f.flush()
            os.fchmod(f.fileno(), mode)
    for path, _text, _mode in pairs:
        os.replace(str(path) + '.new', str(path))
    return end


def isemon_tls_tick(daemon):
    """Every few minutes: this node's own certificate for isemon where mutual
    TLS is on, renewed in time; isemon's certificate made here said before it
    runs out."""
    now = time.time()
    if now - ISEMON_TLS_WORK['at'] < 300:
        return
    ISEMON_TLS_WORK['at'] = now
    store = daemon.store
    if CONFIG.get('isemon') and CONFIG.get('isemon_mtls'):
        before = ISEMON_CLIENT_CRT.stat().st_mtime if ISEMON_CLIENT_CRT.exists() else 0
        isemon_client_cert(store)
        after = ISEMON_CLIENT_CRT.stat().st_mtime if ISEMON_CLIENT_CRT.exists() else 0
        sh = getattr(daemon, 'shipper', None)
        if sh is not None and after != before:
            sh.ctx = None
            for key in list(sh.tcp):
                try:
                    sh.tcp.pop(key).close()
                except (OSError, KeyError):
                    pass
    srv = _meta_obj(store, 'isemon:server')
    left = (float(srv.get('end') or 0) - now) / 86400 if srv else None
    if left is not None and left < 60 and now - ISEMON_TLS_WORK['said'] > 86400 and \
            alerts_lead(store):
        ISEMON_TLS_WORK['said'] = now
        store.add_event('settings', 'isemon\'s certificate from acme\'s authority (%s) ends in %d '
                        'days - make a new bundle for isemon (Settings → isemon → Encrypted '
                        'sending)' % (', '.join(srv.get('names') or []), max(0, int(left))),
                        'warn')


def isemon_rsyslog_conf(port, mtls, peers):
    """What isemon's rsyslog takes it with: its own input on the port, the
    files of the bundle. Per-input stream settings: rsyslog 8.2106 or later
    (AlmaLinux/RHEL 9); the plain input on 514 stays as it is."""
    peer = ('\n      StreamDriver.AuthMode="x509/name"\n      PermittedPeer=[%s]'
            % ', '.join('"%s"' % p for p in peers)) if mtls else \
        '\n      StreamDriver.AuthMode="anon"'
    return ('# /etc/rsyslog.d/10-acme-tls.conf - made by acme %s on %s\n'
            '# The acme nodes send over TLS to %d/tcp. Needs: dnf install rsyslog-gnutls\n'
            'global(\n'
            '  DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/acme/ca.pem"\n'
            '  DefaultNetstreamDriverCertFile="/etc/pki/rsyslog/acme/isemon.crt"\n'
            '  DefaultNetstreamDriverKeyFile="/etc/pki/rsyslog/acme/isemon.key"\n'
            ')\n'
            '# imtcp loaded once in the whole configuration - take this line out if\n'
            '# /etc/rsyslog.conf loads it already.\n'
            'module(load="imtcp")\n'
            'input(type="imtcp" port="%d" name="acme-tls"\n'
            '      StreamDriver.Name="gtls"\n'
            '      StreamDriver.Mode="1"%s)\n'
            % (__version__, time.strftime('%Y-%m-%d'), int(port), int(port), peer))


def isemon_tls_bundle(store, names, port, mtls, passphrase, by):
    """isemon's certificate from acme's authority, its key, the authority, the
    rsyslog configuration and what to do - one ZIP locked with the passphrase
    (the key is in it). The key is not kept here."""
    names = [n.strip().rstrip('.') for n in names if n.strip()]
    if not names:
        raise ValueError('the name isemon is reached by (as in its address here) is needed')
    for n in names:
        _san_ext([n])
    if len(str(passphrase or '')) < 12:
        raise ValueError('the passphrase is 12 characters at least - the key of isemon\'s '
                         'certificate is in the file')
    with HATLS_LOCK:
        ca = hatls_ca(store)
        if not ca['cas'] or float(ca['cas'][0].get('end') or 0) - time.time() < \
                HATLS_CA_ROLL_DAYS * 86400:
            hatls_ca_make(store, by)
    key, crt = hatls_issue(store, names, eku='serverAuth', days=ISEMON_SERVER_DAYS,
                           cn=names[0][:64])
    trust = hatls_trust(hatls_ca(store))
    end = _cert_end(crt)
    peers = _isemon_peer_names(store)
    readme = (
        'isemon over TLS - from acme %s, %s\n\n'
        'isemon.crt  isemon\'s certificate for %s, good until %s\n'
        'isemon.key  its key - for rsyslog alone (0600, root)\n'
        'ca.pem      acme\'s own authority: it signed isemon.crt%s\n'
        '10-acme-tls.conf  the rsyslog configuration\n\n'
        'On the isemon machine, as root:\n'
        '  dnf install rsyslog-gnutls\n'
        '  install -d -m 0750 /etc/pki/rsyslog/acme\n'
        '  install -m 0644 ca.pem isemon.crt /etc/pki/rsyslog/acme/\n'
        '  install -m 0600 isemon.key /etc/pki/rsyslog/acme/\n'
        '  restorecon -R /etc/pki/rsyslog\n'
        '  install -m 0644 10-acme-tls.conf /etc/rsyslog.d/\n'
        '  rsyslogd -N1 && systemctl restart rsyslog\n'
        '  firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload\n\n'
        'The rule that files the acme-certs lines stays as it is: it files the lines that\n'
        'come over TLS the same way.\n'
        'Then on acme: Settings -> isemon -> Encrypted sending -> Try it on every node,\n'
        'then Switch over.\n' % (
            __version__, time.strftime('%Y-%m-%d'), ', '.join(names), stamp(end),
            ' - and, with mutual TLS, the\n             certificates of the acme nodes (%s)'
            % ', '.join(peers) if mtls else '', int(port)))
    files = [('ca.pem', trust.encode()), ('isemon.crt', (crt.strip() + '\n').encode()),
             ('isemon.key', (key.strip() + '\n').encode()),
             ('10-acme-tls.conf', isemon_rsyslog_conf(port, mtls, peers).encode()),
             ('README.txt', readme.encode())]
    blob = zip_aes_write(files, str(passphrase))
    store.set_meta('isemon:server', json.dumps({'names': names, 'end': end, 'at': time.time(),
                                                'by': by, 'mtls': bool(mtls), 'port': int(port)}))
    store.add_event('settings', '%s made a certificate for isemon (%s) from acme\'s authority, '
                    'good until %s, and took it away in a locked file' % (
                        by, ', '.join(names), stamp(end)), 'warn', who=by)
    return blob


def isemon_tls_probe(store, host, port, ca_pem, verify, mtls):
    """A TLS connection to isemon from this node, with these settings: how far
    it went, isemon's certificate, and - with mutual TLS - whether isemon kept
    the connection after seeing this node's."""
    out = {'host': host, 'port': port, 'steps': []}
    began = time.time()

    def step(what, ok, said=''):
        out['steps'].append({'what': what, 'ok': ok, 'said': said,
                             'ms': int((time.time() - began) * 1000)})
    if mtls:
        try:
            isemon_client_cert(store)
            step('this node\'s certificate', True, 'from acme\'s authority')
        except Exception as e:                          # noqa: BLE001
            step('this node\'s certificate', False, str(e)[:200])
            return dict(out, ok=False)
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_pem:
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as e:
            step('the authority', False, 'not a PEM certificate: %s' % str(e)[:120])
            return dict(out, ok=False)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if mtls:
        ctx.load_cert_chain(str(ISEMON_CLIENT_CRT), str(ISEMON_CLIENT_KEY))
    try:
        raw = socket.create_connection((host, int(port)), timeout=6)
    except OSError as e:
        step('connected', False, str(e)[:200])
        return dict(out, ok=False)
    step('connected', True, '%s:%d' % (host, int(port)))
    try:
        try:
            t = ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError as e:
            step('TLS, isemon\'s certificate checked', False, str(e.verify_message or e)[:200])
            return dict(out, ok=False)
        except (ssl.SSLError, OSError) as e:
            step('TLS', False, str(e)[:200])
            return dict(out, ok=False)
        cert = t.getpeercert() or {}
        out.update(version=t.version(), cipher=(t.cipher() or ('',))[0])
        if cert:
            out['cert'] = {
                'subject': ', '.join('%s=%s' % x[0] for x in cert.get('subject') or ()),
                'issuer': ', '.join('%s=%s' % x[0] for x in cert.get('issuer') or ()),
                'end': ssl.cert_time_to_seconds(cert['notAfter']) if cert.get('notAfter')
                else None,
                'names': [v for _k, v in cert.get('subjectAltName') or ()]}
        step('TLS, isemon\'s certificate checked' if verify else 'TLS (the certificate not '
             'checked)', True, '%s, %s' % (out['version'], out['cipher']))
        # A line isemon files as any other test line; with mutual TLS a server
        # that does not take this node's certificate closes the connection.
        line = '<29>%s %s acme[%d]: a TLS test from acme %s on %s - isemon reads nothing from ' \
               'this line\n' % (syslog_stamp(), (str(CONFIG.get('isemon_hostname') or '').strip()
                                                or short_host()), os.getpid(), __version__,
                                node_name())
        try:
            t.sendall(line.encode())
            t.settimeout(1.5)
            try:
                got = t.recv(1)
                if got == b'':
                    step('isemon kept the connection', False, 'it closed it' + (
                        ' - it did not take this node\'s certificate?' if mtls else ''))
                    return dict(out, ok=False)
            except socket.timeout:
                pass
            except ssl.SSLError as e:
                step('isemon kept the connection', False, str(e)[:200])
                return dict(out, ok=False)
        except (OSError, ssl.SSLError) as e:
            step('a test line sent', False, str(e)[:200])
            return dict(out, ok=False)
        step('isemon kept the connection', True, 'a test line sent' + (
            ', this node\'s certificate taken' if mtls else ''))
        try:
            t.close()
        except OSError:
            pass
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return dict(out, ok=True)


def isemon_tls_view(store):
    targets = syslog_targets(CONFIG.get('isemon_targets'))
    nodes = {}
    for n in host_nodes(store):
        c = _meta_obj(store, 'isemon:client:' + n)
        nodes[n] = {'client_end': c.get('end')}
    srv = _meta_obj(store, 'isemon:server')
    return {'on': bool(CONFIG.get('isemon')),
            'targets': [{'host': h, 'port': p, 'proto': pr} for h, p, pr in targets],
            'tls': any(pr == 'tls' for _h, _p, pr in targets),
            'plain': any(pr != 'tls' for _h, _p, pr in targets),
            'verify': bool(CONFIG.get('isemon_verify', 1)), 'mtls': bool(CONFIG.get('isemon_mtls')),
            'ca': 'given' if str(CONFIG.get('isemon_ca') or '').strip() else 'system',
            'ca_is_acme': bool(str(CONFIG.get('isemon_ca') or '').strip()) and
            str(CONFIG.get('isemon_ca') or '').strip() == hatls_trust(hatls_ca(store)).strip(),
            'server': {k: srv.get(k) for k in ('names', 'end', 'at', 'by', 'mtls', 'port')}
            if srv else None,
            'nodes': nodes, 'peers': _isemon_peer_names(store),
            'hisec': hisec_enforced('isemon', store)}


@node_ask_kind('isemon_tls')
def _ask_isemon_tls(daemon, args):
    ca = str(args.get('ca_pem') or '')
    if args.get('ca_source') == 'acme':
        ca = hatls_trust(hatls_ca(daemon.store))
    return isemon_tls_probe(daemon.store, str(args.get('host') or ''), int(args.get('port') or 6514),
                            ca, bool(args.get('verify', True)), bool(args.get('mtls')))

