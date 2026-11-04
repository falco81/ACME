# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- going out through a proxy (1.0.166) --------------------------------------------
# Settings → Proxy: each thing that may go through it has a switch of its own
# (1.0.202), all off by default - the proxy switched on with none of them is
# used nowhere. 'update' the new versions of acme, 'os' dnf or apt (handed to
# the root helper in its request, never on a command line), 'acme' the CA,
# 'acme_dns' the DNS APIs of DNS-01, 'sms' the HTTP SMS gateway. Anything else
# - and anything asked without a purpose - goes straight: mail, Active
# Directory, the database, syslog, isemon, the backups, the other node, the
# VIP address's check never go through it.
PROXY_FOR = {'update': 'proxy_update', 'os': 'proxy_os', 'acme': 'proxy_acme',
             'acme_dns': 'proxy_acme_dns', 'sms': 'proxy_sms'}


def proxy_set():
    """The proxy switched on with an address - whatever goes through it."""
    return bool(CONFIG.get('proxy')) and bool(str(CONFIG.get('proxy_url') or '').strip())


def proxy_on(purpose='update'):
    key = PROXY_FOR.get(purpose)
    if not key or not proxy_set():
        return False
    return bool(CONFIG.get(key))


def proxy_full(purpose='update'):
    """The proxy's address with its user and password in it, for urllib, dnf
    and apt - '' where none is to be used. Never logged, never shown."""
    if not (proxy_set() if purpose == 'try' else proxy_on(purpose)):
        return ''
    url = str(CONFIG.get('proxy_url') or '').strip().rstrip('/')
    user = str(CONFIG.get('proxy_user') or '').strip()
    if not user:
        return url
    pw = unseal_secret(CONFIG.get('proxy_password') or '') or ''
    scheme, _, rest = url.partition('://')
    return '%s://%s:%s@%s' % (scheme, urllib.parse.quote(user, safe=''),
                              urllib.parse.quote(pw, safe=''), rest)


def proxy_no_list():
    return [w.strip().lower() for w in re.split(r'[\s,;]+', str(CONFIG.get('proxy_no') or ''))
            if w.strip()]


def proxy_skips(host):
    """Whether this host is reached straight, as proxy_no says."""
    host = str(host or '').strip('[]').lower()
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for one in proxy_no_list():
        if one == '*':
            return True
        if ip is not None and ('/' in one or re.match(r'^[0-9a-f.:]+\Z', one)):
            try:
                if ip in ipaddress.ip_network(one.strip('[]'), strict=False):
                    return True
            except ValueError:
                pass
            continue
        one = one.lstrip('*')
        if one.startswith('.'):
            if host.endswith(one) or host == one[1:]:
                return True
        elif host == one:
            return True
    return False


class _ProxyOnly(urllib.request.ProxyHandler):
    """ProxyHandler without its look at no_proxy in the environment: only
    proxy_no says what goes straight."""
    def proxy_open(self, req, proxy, type):
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if user and password:
            creds = base64.b64encode(('%s:%s' % (urllib.parse.unquote(user),
                                                 urllib.parse.unquote(password))).encode())
            req.add_header('Proxy-authorization', 'Basic ' + creds.decode('ascii'))
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type or req.type)
        return None


class _NoCredsRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect to another host, or from https to http, without the request's credentials
    (1.0.234): urllib carried the SMS gateway's or a CA's credentials wherever the answer pointed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg,
                                                                  headers, newurl)
        if new is None:
            return None
        a, b = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(new.full_url)
        if (a.hostname or '').lower() != (b.hostname or '').lower() or a.scheme != b.scheme or \
                (a.port or 0) != (b.port or 0):
            for k in list(new.headers):
                if k.lower() in ('authorization', 'proxy-authorization', 'cookie'):
                    del new.headers[k]
            for k in list(getattr(new, 'unredirected_hdrs', {}) or {}):
                if k.lower() in ('authorization', 'proxy-authorization', 'cookie'):
                    del new.unredirected_hdrs[k]
        return new


def url_open(req, timeout=30, context=None, purpose=''):
    """urllib.request.urlopen - straight, unless asked for a purpose whose
    switch is on, a proxy set and the host not one reached straight; never
    through what the environment says."""
    if not isinstance(req, urllib.request.Request):
        req = urllib.request.Request(req)
    proxy = proxy_full(purpose)
    host = urllib.parse.urlsplit(req.full_url).hostname or ''
    handlers = [_ProxyOnly(
        {'http': proxy, 'https': proxy} if proxy and not proxy_skips(host) else {}),
        _NoCredsRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def proxy_try(url=''):
    """Settings → Proxy → Try it (1.0.169): an address asked the way acme asks
    the web - through the proxy where one is set and the address is not one
    reached straight, else straight - one step at a time: the name looked up,
    the connection, the tunnel through the proxy, TLS and the certificate,
    the answer. Always tried; each step with how long it took."""
    url = str(url or '').strip() or online_url() or 'https://github.com/'
    if not re.match(r'^https?://[^\s/]+[^\s]*\Z', url):
        raise ValueError('an address starting https:// (or http://)')
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ''
    tls_on = u.scheme == 'https'
    port = u.port or (443 if tls_on else 80)
    via, why = '', ''
    # The proxy itself tried, whatever is switched on to go through it.
    if not proxy_set():
        why = 'no proxy is set' if not CONFIG.get('proxy') else 'the proxy has no address'
    elif proxy_skips(host):
        why = '%s is in the list reached straight' % host
    else:
        via = proxy_full('try')
    px = urllib.parse.urlsplit(via) if via else None
    out = {'url': url, 'host': host, 'port': port, 'mode': 'proxy' if via else 'direct',
           'why_direct': why, 'node': node_name(), 'steps': [], 'ok': False,
           'proxy': '%s:%d' % (px.hostname, px.port or 3128) if px else '',
           'proxy_auth': bool(px and px.username)}
    began = time.time()
    sock = [None]

    def step(what, fn):
        t0 = time.time()
        try:
            said = fn() or ''
        except Exception as e:                          # noqa: BLE001
            out['steps'].append({'what': what, 'ok': False, 'ms': int((time.time() - t0) * 1000),
                                 'said': str(getattr(e, 'reason', '') or e)[:300]})
            raise
        out['steps'].append({'what': what, 'ok': True, 'ms': int((time.time() - t0) * 1000),
                             'said': said})

    def resolve(name, p):
        got = socket.getaddrinfo(name, p, 0, socket.SOCK_STREAM)
        addrs = []
        for g in got:
            if g[4][0] not in addrs:
                addrs.append(g[4][0])
        out.setdefault('addrs', {})[name] = addrs
        return ', '.join(addrs[:4])

    def connect(name, p):
        sock[0] = socket.create_connection((name, p), timeout=10)
        sock[0].settimeout(15)
        peer = sock[0].getpeername()
        return '%s port %d' % (peer[0], peer[1])

    def read_head():
        data = b''
        while b'\r\n\r\n' not in data and len(data) < 65536:
            chunk = sock[0].recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        m = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)$', line)
        if not m:
            raise ValueError('no HTTP answer: %r' % line[:80])
        return int(m.group(1)), m.group(2).strip(), data

    def auth_header():
        if not (px and px.username):
            return ''
        creds = '%s:%s' % (urllib.parse.unquote(px.username), urllib.parse.unquote(px.password or ''))
        return 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(creds.encode()).decode()

    try:
        if via:
            step('the proxy looked up (%s)' % px.hostname, lambda: resolve(px.hostname, px.port or 3128))
            step('connected to the proxy', lambda: connect(px.hostname, px.port or 3128))
            if tls_on:
                def tunnel():
                    sock[0].sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s'
                                     'User-Agent: acme/%s (+proxy check)\r\n\r\n' % (
                                         host, port, host, port, auth_header(), __version__)).encode())
                    code, words, _ = read_head()
                    if code == 407:
                        raise ValueError('the proxy asks for a user name and a password (407) - '
                                         'they are %s' % ('wrong' if px.username else 'missing'))
                    if code != 200:
                        raise ValueError('the proxy said %d %s' % (code, words))
                    return '%d %s%s' % (code, words, ' - with the user name and password'
                                        if px.username else '')
                step('a tunnel through the proxy to %s:%d' % (host, port), tunnel)
        else:
            step('%s looked up' % host, lambda: resolve(host, port))
            step('connected to %s' % host, lambda: connect(host, port))
        if tls_on:
            def handshake():
                ctx = ssl.create_default_context()
                sock[0] = ctx.wrap_socket(sock[0], server_hostname=host)
                c = sock[0].getpeercert() or {}
                subj = dict(x[0] for x in c.get('subject', ()) if x)
                iss = dict(x[0] for x in c.get('issuer', ()) if x)
                out['tls'] = {'version': sock[0].version(), 'cipher': (sock[0].cipher() or [''])[0],
                              'subject': subj.get('commonName', ''),
                              'issuer': iss.get('organizationName') or iss.get('commonName', ''),
                              'until': c.get('notAfter', '')}
                return '%s, %s - %s, by %s' % (out['tls']['version'], out['tls']['cipher'],
                                               out['tls']['subject'], out['tls']['issuer'])
            step('TLS, the certificate of %s checked' % host, handshake)

        def ask():
            path = (u.path or '/') + ('?' + u.query if u.query else '')
            target = url if (via and not tls_on) else path
            sock[0].sendall(('HEAD %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: acme/%s (+proxy check)'
                             '\r\nConnection: close\r\n\r\n' % (
                                 target, u.netloc.split('@')[-1],
                                 auth_header() if (via and not tls_on) else '', __version__)).encode())
            code, words, _ = read_head()
            out['status'] = code
            if code == 407:
                raise ValueError('the proxy asks for a user name and a password (407)')
            return '%d %s' % (code, words)
        step('asked for %s' % (u.path or '/'), ask)
        out['ok'] = True
    except Exception:                                   # noqa: BLE001
        pass
    finally:
        try:
            if sock[0]:
                sock[0].close()
        except OSError:
            pass
    out['ms'] = int((time.time() - began) * 1000)
    return out



