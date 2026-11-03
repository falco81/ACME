# -*- coding: utf-8 -*-
"""TLS at once on any port, and HTTPS - with a request, when asked: its method,
path, Host header and headers, the status and words expected back."""
from __future__ import annotations

import re

from acmelib.plugins.base import Check, PluginError, field
from acmelib.plugins.checks import _tls


class TlsCheck(Check):
    kind = 'tls'
    title = 'TLS (any port)'
    protocol = 'TLS'
    default_port = 443
    description = ('TLS at once on any port - a web server, LDAPS, a reverse proxy, MQTT over '
                   'TLS, an API: the certificate it serves compared with the one acme keeps.')
    fields = _tls.fields(443)

    def served(self, host, port, sni, verify=True):
        t = float(self.c('timeout', 15) or 15)
        sock = _tls.connect(host, port, t)
        return _tls.tls(sock, sni, verify, t)


HTTP_FIELDS = [
    field('http', 'Ask over HTTP too', 'bool', default=False,
          help='After TLS, an HTTP request: the answer is checked as set below - the site '
               'answers, not only its certificate. On: the method, path, Host header and other '
               'headers, the status and words expected.'),
    field('method', 'Method', 'select', default='HEAD', show_if={'http': [True]},
          options=[['HEAD', 'HEAD'], ['GET', 'GET'], ['OPTIONS', 'OPTIONS']]),
    field('path', 'Path', 'text', default='/', show_if={'http': [True]}, placeholder='/health'),
    field('host_header', 'Host header', 'text', show_if={'http': [True]},
          placeholder='empty: the SNI',
          help='The Host the request names - a virtual host other than the SNI, say.'),
    field('headers', 'More headers', 'list', show_if={'http': [True]},
          placeholder='User-Agent: acme-check\nX-Forwarded-Proto: https',
          help='One a line, "Name: value".'),
    field('expect_status', 'Status expected', 'text', default='200-399',
          show_if={'http': [True]}, placeholder='200,301-302',
          help='Codes and ranges, comma between them. Empty: any answer.'),
    field('body_contains', 'The answer holds', 'text', show_if={'http': [True]},
          help='Words the answer must hold (GET only; the first 64 KB read).'),
]


def status_ok(code, want):
    want = str(want or '').strip()
    if not want:
        return True
    for part in want.split(','):
        part = part.strip()
        m = re.match(r'^(\d{3})(?:\s*-\s*(\d{3}))?$', part)
        if m and int(m.group(1)) <= code <= int(m.group(2) or m.group(1)):
            return True
    return False


class HttpsCheck(TlsCheck):
    kind = 'https'
    title = 'HTTPS'
    protocol = 'HTTPS'
    default_port = 443
    description = ('A web server: TLS on port 443 (or another), the name sent as SNI - the '
                   'certificate a browser would get, and an HTTP request with its own Host '
                   'header when asked.')
    fields = _tls.fields(443, HTTP_FIELDS)

    def served(self, host, port, sni, verify=True):
        t = float(self.c('timeout', 15) or 15)
        ask = str(self.c('http', '')).lower() in ('1', 'true', 'yes', 'on')
        sock = _tls.connect(host, port, t)
        out = _tls.tls(sock, sni, verify, t, keep=ask)
        if not ask:
            return out
        s = out.pop('sock')
        try:
            out['http'] = self.request(s, sni if sni not in ('', '-') else host, port, t)
        finally:
            try:
                s.close()
            except OSError:
                pass
        return out

    def request(self, s, name, port, timeout):
        method = str(self.c('method') or 'HEAD').upper()
        path = str(self.c('path') or '/')
        if not path.startswith('/'):
            path = '/' + path
        hosth = str(self.c('host_header') or '').strip() or (
            name if int(port) == 443 else '%s:%s' % (name, port))
        lines = ['%s %s HTTP/1.1' % (method, path), 'Host: %s' % hosth]
        extra = self.c('headers') or []
        if isinstance(extra, str):
            extra = extra.splitlines()
        have = set()
        for h in extra:
            h = str(h).strip()
            if not h:
                continue
            if ':' not in h or '\r' in h or '\n' in h:
                raise PluginError('"%s" is not a header (Name: value)' % h, retry=False)
            have.add(h.split(':', 1)[0].strip().lower())
            lines.append(h)
        if 'user-agent' not in have:
            lines.append('User-Agent: acme-check')
        lines += ['Accept: */*', 'Connection: close', '', '']
        s.settimeout(timeout)
        try:
            s.sendall('\r\n'.join(lines).encode('utf-8'))
            got = b''
            while len(got) < 65536:
                part = s.recv(16384)
                if not part:
                    break
                got += part
                if method == 'HEAD' and b'\r\n\r\n' in got:
                    break
        except OSError as e:
            raise PluginError('the HTTP request got no answer: %s' % e)
        head, _, body = got.partition(b'\r\n\r\n')
        first = head.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        m = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$', first)
        if not m:
            raise PluginError('the answer is not HTTP: %r' % first[:80])
        code = int(m.group(1))
        res = {'status': code, 'reason': (m.group(2) or '')[:80], 'host_header': hosth,
               'path': path, 'method': method}
        hdrs = {}
        for ln in head.split(b'\r\n')[1:]:
            k, _, v = ln.decode('latin-1', 'replace').partition(':')
            hdrs[k.strip().lower()] = v.strip()
        if hdrs.get('location'):
            res['location'] = hdrs['location'][:300]
        if hdrs.get('server'):
            res['server'] = hdrs['server'][:120]
        want = self.c('expect_status', '200-399')
        if not status_ok(code, want):
            res['fault'] = 'it answered %d %s, not %s' % (code, res['reason'], want)
        words = str(self.c('body_contains') or '')
        if words and not res.get('fault') and method == 'GET' and \
                words.encode('utf-8') not in body:
            res['fault'] = 'the answer does not hold "%s"' % words
        return res
