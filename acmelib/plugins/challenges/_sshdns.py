# -*- coding: utf-8 -*-
"""
What ssh_dns.py (DNS-01 by commands on the DNS server over SSH) stands on -
the name starts with "_": the registry does not take it for a module.

    edit_zone_text()    a zone file's text with acme's own TXT line added or taken
                        away and the SOA serial raised - refused when the file is
                        not a plain zone file this can read safely
    edit_dnsmasq_text() the same for the txt-record lines of acme's dnsmasq file
    write_script()      the shell script that puts such a file in place: the file
                        checked unchanged, a backup kept, the new one checked (named-
                        checkzone / nsd-checkzone / dnsmasq --test), the server told,
                        the old one put back when that fails
    parse_named_conf()  what `named-checkconf -p` prints, read: zones, keys, options
    Discovery           what runs on the DNS server, found by read-only commands only
                        (READ_ONLY: every command is checked against it before it
                        is sent, and refused when it is not on it)
"""
from __future__ import annotations

import datetime
import hashlib
import os
import re
import secrets
import time

from acmelib.plugins.base import PluginError
from acmelib.plugins.challenges import _dns as D

# What every command for a Unix server starts with: the sbin directories where a
# DNS server's tools live (an account that is not root has no /usr/sbin in PATH).
PATH_PRE = 'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"; export PATH; '
MARK = '; acme-challenge'
MAX_ZONE_BYTES = 8 * 1024 * 1024

NAME_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*$')
PATH_RE = re.compile(r'^/[A-Za-z0-9_./+@:-]{0,1000}$')
# A command of the settings (rndc, a reload): words without anything a shell acts on.
CMD_RE = re.compile(r'^[A-Za-z0-9_./=:@+ -]{1,300}$')


def shq(s):
    """A word for a POSIX shell (as _common.shq)."""
    s = str(s)
    if s and re.match(r'^[A-Za-z0-9_@%+=:,./-]+$', s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def safe_name(n, what='name'):
    n = D.norm(n)
    if not NAME_RE.match(n or ''):
        raise PluginError('%r is not a %s acme puts on a command line' % (n, what), retry=False)
    return n


def safe_path(p, what='path'):
    p = str(p or '').strip()
    if not PATH_RE.match(p) or '/../' in p + '/' or '/./' in p + '/' or '//' in p:
        raise PluginError('%r is not a %s acme uses (an absolute path of plain letters)'
                          % (p, what), retry=False)
    return p


def safe_cmd(c, what='command'):
    c = ' '.join(str(c or '').split())
    if not CMD_RE.match(c) or c.startswith('-'):
        raise PluginError('%r is not a %s acme runs (words and paths only - no ; | & $ ` > <)'
                          % (c, what), retry=False)
    return c


def text_of(v):
    if isinstance(v, bytes):
        return v.decode('utf-8', 'replace')
    return str(v or '')


def sha256(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# A zone file, edited: only acme's own lines, the serial raised
# ---------------------------------------------------------------------------
class NotPlain(PluginError):
    """A zone file this will not edit."""
    def __init__(self, path, why):
        PluginError.__init__(self, '%s is not a zone file acme edits safely (%s) - use a dynamic '
                                   'zone (nsupdate) for it instead' % (path, why), retry=False)


def _records(text, path):
    """The logical records of a zone file: [(tokens, starts_with_blank)], a token
    being (text, start, end). Comments, quotes and parentheses as RFC 1035 has
    them; NotPlain where it cannot be read whole."""
    out = []
    i, n = 0, len(text)
    toks, depth, line_start, blank_start = [], 0, True, False
    blank_start0 = False
    while i < n:
        c = text[i]
        if line_start:
            blank_start = c in ' \t' and depth == 0
            line_start = False
        if c == '\n':
            if depth == 0:
                if toks:
                    out.append((toks, blank_start0))
                toks = []
            line_start = True
            i += 1
            continue
        if c in ' \t\r':
            i += 1
            continue
        if c == ';':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '(':
            depth += 1
            i += 1
            continue
        if c == ')':
            depth -= 1
            if depth < 0:
                raise NotPlain(path, 'a ")" without its "(" near character %d' % i)
            i += 1
            continue
        if not toks:
            blank_start0 = blank_start
        start = i
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                if i < n and text[i] == '\n':
                    raise NotPlain(path, 'a quoted string over two lines')
                i += 1
            if i >= n:
                raise NotPlain(path, 'a quote that does not end')
            i += 1
        else:
            while i < n and text[i] not in ' \t\r\n;()"':
                if text[i] == '\\':
                    i += 1
                i += 1
        toks.append((text[start:i], start, i))
    if depth:
        raise NotPlain(path, 'a "(" that does not end')
    if toks:
        out.append((toks, blank_start0))
    return out


def find_serial(text, path='the zone file'):
    """(serial, start, end) of the zone file's one SOA record; NotPlain otherwise."""
    soa = []
    for toks, _blank in _records(text, path):
        first = toks[0][0]
        if first.upper() == '$INCLUDE':
            raise NotPlain(path, 'it has an $INCLUDE')
        if first.startswith('$'):
            continue
        words = [t[0].upper() for t in toks[:5]]
        if 'SOA' in words:
            k = words.index('SOA')
            if len(toks) < k + 4:
                raise NotPlain(path, 'its SOA record is cut short')
            soa.append(toks[k + 3])
    if not soa:
        raise NotPlain(path, 'no SOA record in it')
    if len(soa) > 1:
        raise NotPlain(path, '%d SOA records in it' % len(soa))
    serial, start, end = soa[0]
    if not re.match(r'^\d{1,10}$', serial) or int(serial) > 0xFFFFFFFF:
        raise NotPlain(path, 'its SOA serial "%s" is not a plain number' % serial)
    return int(serial), start, end


def next_serial(old, mode='auto', now=None):
    """The serial after `old`: 'date' YYYYMMDDnn, 'unixtime', 'increment' (+1);
    'auto' - a date where the serial looks like one, else +1."""
    now = time.time() if now is None else now
    day = int(datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime('%Y%m%d')) * 100
    if mode == 'auto':
        s = '%d' % old
        mode = 'increment'
        if len(s) == 10:
            try:
                datetime.datetime.strptime(s[:8], '%Y%m%d')
                if 1990 <= int(s[:4]) <= 2200:
                    mode = 'date'
            except ValueError:
                pass
    if mode == 'date':
        new = max(day, old + 1)
    elif mode == 'unixtime':
        new = max(int(now), old + 1)
    else:
        new = old + 1
    if new > 0xFFFFFFFF or new - old >= 2 ** 31:
        raise PluginError('the SOA serial %d cannot be raised that way (%s): set the serial by '
                          'hand or choose another way of raising it' % (old, mode), retry=False)
    return new


def acme_line(fqdn, value, ttl):
    return '%s. %d IN TXT "%s" %s' % (D.norm(fqdn), int(ttl), value, MARK)


def _is_ours(line, fqdn, value):
    return re.match(r'^%s\.\s+\d+\s+IN\s+TXT\s+"%s"\s*%s(\s.*)?$' % (
        re.escape(D.norm(fqdn)), re.escape(value), re.escape(MARK)), line.rstrip('\r'),
        re.I) is not None


def edit_zone_text(text, fqdn, value, ttl, op, path='the zone file', serial_mode='auto',
                   now=None):
    """(new text, changed, old serial, new serial): the TXT line of acme's own
    added (op 'add') or taken away ('del'), nothing else touched; the serial
    raised only when something changed."""
    if len(text) > MAX_ZONE_BYTES:
        raise NotPlain(path, 'it is larger than %d MB' % (MAX_ZONE_BYTES // 1048576))
    if '\0' in text or '�' in text:
        raise NotPlain(path, 'it is not a text file (a raw or map zone, or not UTF-8)')
    if not re.match(r'^[A-Za-z0-9_.+/=:-]{1,255}$', str(value or '')):
        raise PluginError('a TXT value acme will not write: %r' % value, retry=False)
    safe_name(fqdn)
    old, _s0, _s1 = find_serial(text, path)
    nl = '\r\n' if text.count('\r\n') > text.count('\n') // 2 and '\r\n' in text else '\n'
    lines = text.split('\n')
    ours = [i for i, ln in enumerate(lines) if _is_ours(ln, fqdn, value)]
    if op == 'add':
        if ours:
            return text, False, old, old
        body = text
        if body and not body.endswith('\n'):
            body += nl
        body += acme_line(fqdn, value, ttl) + nl
    else:
        if not ours:
            return text, False, old, old
        drop = set(ours)
        body = '\n'.join(ln for i, ln in enumerate(lines) if i not in drop)
    new = next_serial(old, serial_mode, now)
    again, s0, s1 = find_serial(body, path)        # where the serial is now
    if again != old:
        raise NotPlain(path, 'its SOA changed while it was edited')
    body = body[:s0] + '%d' % new + body[s1:]
    return body, True, old, new


DNSMASQ_HEAD = ('# acme: the TXT records of DNS-01 validations, put in and taken away by acme '
                '(ssh_dns). Lines of its own only.')


def edit_dnsmasq_text(text, fqdn, value, op):
    """(new text, changed): the txt-record line of acme's own in its dnsmasq file."""
    if not re.match(r'^[A-Za-z0-9_.+/=:-]{1,255}$', str(value or '')):
        raise PluginError('a TXT value acme will not write: %r' % value, retry=False)
    fqdn = safe_name(fqdn)
    text = text or ''
    if '\0' in text or '�' in text:
        raise PluginError('the dnsmasq file is not a text file', retry=False)
    line = 'txt-record=%s,"%s"' % (fqdn, value)
    lines = [ln for ln in text.split('\n')]
    while lines and lines[-1] == '':
        lines.pop()
    have = [i for i, ln in enumerate(lines) if ln.strip().lower() == line.lower()]
    if op == 'add':
        if have:
            return text, False
        if not lines:
            lines = [DNSMASQ_HEAD]
        lines.append(line)
    else:
        if not have:
            return text, False
        lines = [ln for i, ln in enumerate(lines) if i not in set(have)]
    return '\n'.join(lines) + '\n', True


def write_script(path, content, old_sha, check=None, reload=None, check_after=False):
    """The shell script (POSIX sh, run by `sh -s`) that puts `content` in `path`:
    the file must still be what was read (old_sha; None: there was none), a copy
    kept as .NAME.acme-bak beside it, the new one written to .NAME.acme-new,
    checked (`check`, "$t" the new file; check_after: once it is in place - the
    whole configuration is checked then), moved into place and `reload` run; a
    failed check or reload puts the old one back. Nothing but those two files of
    acme's own is ever removed."""
    path = safe_path(path)
    delim = 'ACME_EOF_' + secrets.token_hex(6)
    while delim in content:
        delim = 'ACME_EOF_' + secrets.token_hex(6)
    if content and not content.endswith('\n'):
        content += '\n'
    restore = ('if [ "$had" = 1 ]; then cp -p "$b" "$f"; else rm -f "$f"; fi')
    out = ['set -u', PATH_PRE.strip(), 'umask 022',
           'f=%s' % shq(path),
           'd=$(dirname -- "$f"); n=$(basename -- "$f")',
           't="$d/.$n.acme-new"; b="$d/.$n.acme-bak"',
           'had=0; [ -e "$f" ] && had=1',
           'if [ "$had" = 1 ]; then',
           '  if [ ! -f "$f" ] || [ -L "$f" ]; then echo "acme: $f is not a plain file" >&2; '
           'exit 3; fi',
           '  s=$( (sha256sum 2>/dev/null || shasum -a 256) < "$f" | cut -c1-64)',
           'else s=none; fi',
           'if [ "$s" != %s ]; then echo "acme: $f was changed by something else since it was '
           'read - nothing written, try again" >&2; exit 4; fi' % shq(old_sha or 'none'),
           'if [ "$had" = 1 ]; then',
           '  cp -p "$f" "$b" && cp -p "$f" "$t" || { rm -f "$t"; echo "acme: no copy of $f '
           'could be made beside it" >&2; exit 5; }',
           'fi',
           'cat > "$t" <<\'%s\' || { rm -f "$t"; echo "acme: $t could not be written" >&2; '
           'exit 5; }' % delim]
    if content:
        out.append(content[:-1])                    # the here-doc gives each line its newline
    out.append(delim)
    if check and not check_after:
        out.append('o=$(%s 2>&1) || { echo "$o" >&2; rm -f "$t"; echo "acme: the check '
                   'refused the new file - nothing changed" >&2; exit 6; }' % (check,))
    out.append('mv -f "$t" "$f" || { rm -f "$t"; echo "acme: $f could not be put in place" '
               '>&2; exit 5; }')
    if check and check_after:
        out.append('o=$(%s 2>&1) || { echo "$o" >&2; %s; echo "acme: the check refused '
                   'it - the file is back as it was" >&2; exit 6; }' % (check, restore))
    if reload:
        out.append('o=$(%s 2>&1) || { echo "$o" >&2; %s; %s >/dev/null 2>&1; echo "acme: '
                   'the server did not take it - the file is back as it was" >&2; exit 7; }'
                   % (reload, restore, reload))
    out.append('echo "acme: $f written"')
    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
# named.conf as `named-checkconf -p` prints it
# ---------------------------------------------------------------------------
def _conf_tokens(text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == '#' or text.startswith('//', i):
            while i < n and text[i] != '\n':
                i += 1
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
        elif c in '{};':
            yield c
            i += 1
        elif c == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == '\\' and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            yield ('"', ''.join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in '{};"':
                j += 1
            yield text[i:j]
            i = j


def _conf_block(toks, it):
    """Statements until '}' (or the end): each a list of words and nested blocks."""
    out, cur = [], []
    for t in it:
        if t == ';':
            if cur:
                out.append(cur)
            cur = []
        elif t == '{':
            cur.append(_conf_block(toks, it))
        elif t == '}':
            if cur:
                out.append(cur)
            return out
        else:
            cur.append(t[1] if isinstance(t, tuple) else t)
    if cur:
        out.append(cur)
    return out


def _words(st):
    return [w for w in st if isinstance(w, str)]


def _blocks(st):
    return [w for w in st if isinstance(w, list)]


def _find(stmts, name):
    return [s for s in stmts if s and isinstance(s[0], str) and s[0].lower() == name]


def parse_named_conf(text):
    """{'directory', 'session_keyfile', 'zones': [{name, view, type, file, policy:
    ['local'] | [('grant', key, ...)], allow_update: [...], primaries}], 'keys':
    [{name, algorithm}]} - secrets are never kept."""
    toks = list(_conf_tokens(text or ''))
    top = _conf_block(toks, iter(toks))
    out = {'directory': '', 'session_keyfile': '', 'zones': [], 'keys': []}
    for opt in _find(top, 'options'):
        for b in _blocks(opt):
            for st in b:
                w = _words(st)
                if len(w) >= 2 and w[0] == 'directory':
                    out['directory'] = w[1]
                if len(w) >= 2 and w[0] == 'session-keyfile':
                    out['session_keyfile'] = w[1]
    for k in _find(top, 'key'):
        w = _words(k)
        alg = ''
        for b in _blocks(k):
            for st in b:
                sw = _words(st)
                if len(sw) >= 2 and sw[0] == 'algorithm':
                    alg = sw[1]
        if len(w) >= 2:
            out['keys'].append({'name': w[1], 'algorithm': alg})

    def zones(stmts, view):
        for z in _find(stmts, 'zone'):
            w = _words(z)
            if len(w) < 2:
                continue
            zone = {'name': D.norm(w[1]), 'view': view, 'type': '', 'file': '', 'policy': [],
                    'allow_update': [], 'primaries': []}
            for b in _blocks(z):
                for st in b:
                    sw = _words(st)
                    if not sw:
                        continue
                    key = sw[0].lower()
                    if key == 'type' and len(sw) > 1:
                        zone['type'] = sw[1].lower()
                    elif key == 'file' and len(sw) > 1:
                        zone['file'] = sw[1]
                    elif key == 'update-policy':
                        if len(sw) > 1 and sw[1].lower() == 'local':
                            zone['policy'].append('local')
                        for inner in _blocks(st):
                            for rule in inner:
                                rw = _words(rule)
                                if len(rw) >= 2:
                                    zone['policy'].append(tuple(rw))
                    elif key == 'allow-update':
                        for inner in _blocks(st):
                            for el in inner:
                                ew = _words(el)
                                if ew:
                                    zone['allow_update'].append(' '.join(ew))
                    elif key in ('primaries', 'masters'):
                        for inner in _blocks(st):
                            for el in inner:
                                ew = _words(el)
                                if ew:
                                    zone['primaries'].append(ew[0])
            out['zones'].append(zone)

    zones(top, '')
    for v in _find(top, 'view'):
        w = _words(v)
        for b in _blocks(v):
            zones(b, w[1] if len(w) > 1 else '')
    return out


def zone_keys(zone):
    """The key names a BIND zone takes updates signed by."""
    out = []
    for rule in zone.get('policy') or []:
        if isinstance(rule, tuple) and len(rule) >= 2 and rule[0].lower() == 'grant':
            out.append(rule[1])
    for a in zone.get('allow_update') or []:
        bits = a.split()
        if len(bits) >= 2 and bits[0].lower() == 'key':
            out.append(bits[1])
    return [k for i, k in enumerate(out) if k not in out[:i]]


# ---------------------------------------------------------------------------
# ls -lnd, read
# ---------------------------------------------------------------------------
LS_RE = re.compile(r'^([-dlcbps])([rwxsStT-]{9})[.+@]?\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+.*?\s(/.*)$')


def parse_ls(out):
    """{path: {'kind', 'mode', 'uid', 'gid'}} of `ls -lnd -- PATHS`."""
    got = {}
    for line in text_of(out).splitlines():
        m = LS_RE.match(line.strip())
        if m:
            path = m.group(5)
            if m.group(1) == 'l' and ' -> ' in path:
                path = path.split(' -> ', 1)[0]
            got[path] = {'kind': m.group(1), 'mode': m.group(2), 'uid': int(m.group(3)),
                         'gid': int(m.group(4))}
    return got


def may(entry, uid, gids, what):
    """Whether uid (in gids) may 'r' or 'w' the entry of parse_ls."""
    if entry is None:
        return False
    if uid == 0:
        return True
    i = {'r': 0, 'w': 1, 'x': 2}[what]
    m = entry['mode']
    if entry['uid'] == uid:
        return m[i] not in '-ST' if what == 'x' else m[i] != '-'
    if entry['gid'] in gids:
        return m[3 + i] not in '-ST' if what == 'x' else m[3 + i] != '-'
    return m[6 + i] not in '-T' if what == 'x' else m[6 + i] != '-'


# ---------------------------------------------------------------------------
# Discovery: read-only, every command checked
# ---------------------------------------------------------------------------
_W = r"(?:[A-Za-z0-9_@%+=:,./-]+|'[^']*')"        # one word as shq() makes it
TOOLS = ('named', 'named-checkconf', 'named-checkzone', 'rndc', 'nsupdate', 'pdnsutil',
         'pdns_server', 'pdns_control', 'knotc', 'knotd', 'nsd', 'nsd-checkconf',
         'nsd-checkzone', 'nsd-control', 'dnsmasq', 'unbound', 'unbound-control', 'systemctl',
         'pgrep', 'sudo', 'timeout', 'sha256sum', 'curl', 'powershell')
TOOLS_PROBE = 'for c in %s; do command -v "$c"; done' % ' '.join(TOOLS)
UNITS = ('named', 'bind9', 'pdns', 'knot', 'nsd', 'dnsmasq', 'unbound')
UNITS_PROBE = 'systemctl is-active ' + ' '.join(UNITS)
PROCS_PROBE = "pgrep -l -x 'named|pdns_server|knotd|nsd|nsd: main|dnsmasq|unbound'"
KEY_GLOBS = ('/etc/bind/*.key', '/etc/bind/keys/*.key', '/etc/named/*.key', '/etc/named*.key',
             '/var/named/*.key', '/var/lib/bind/*.key', '/usr/local/etc/namedb/*.key')
KEYS_PROBE = "grep -sH -E '^[[:space:]]*key[[:space:]]' -- " + ' '.join(KEY_GLOBS)
PDNS_KEYS = "'^[[:space:]]*(api|webserver|webserver-address|webserver-port|launch)[[:space:]]*='"
DNSMASQ_KEYS = ("'^[[:space:]]*(conf-dir|conf-file|auth-zone|auth-server|local|domain|"
                "txt-record|port)='")
WIN_PROBE = ('powershell -NoProfile -NonInteractive -Command "Get-DnsServerZone | '
             'ForEach-Object { $_.ZoneName + \';\' + $_.ZoneType + \';\' + $_.IsDsIntegrated + '
             '\';\' + $_.IsAutoCreated + \';\' + $_.IsReverseLookupZone }"')

READ_ONLY = [re.compile('^%s$' % p) for p in (
    r'uname -s', r'id -u', r'id -un', r'id -G', r'true',
    re.escape(TOOLS_PROBE), re.escape(UNITS_PROBE), re.escape(PROCS_PROBE),
    r'named -v', r'named-checkconf -p( %s)?' % _W,
    r'ls -lnd --( %s){1,200}' % _W,
    re.escape(KEYS_PROBE),
    r'pdns_server --version', r'pdnsutil( --config-dir=%s)? (list-all-zones|show-zone %s)' % (_W, _W),
    r'grep -hsE %s( %s){1,4}' % (re.escape(PDNS_KEYS), _W) + r'( /etc/powerdns/pdns\.d/\*\.conf|'
    r' %s/pdns\.d/\*\.conf)?' % _W,
    r'knotc( -c %s)?( -s %s)? (-V|conf-read zone\.domain|zone-status)' % (_W, _W),
    r'nsd -v', r'nsd-checkconf (-o zones|-o zonesdir|-z %s -o zonefile|-z %s -o request-xfr) %s'
    % (_W, _W, _W),
    r'dnsmasq --version', r'grep -hsE %s( %s){1,3} /etc/dnsmasq\.d/\*\.conf' % (
        re.escape(DNSMASQ_KEYS), _W),
    r'unbound -V', r'unbound-control( -c %s)? (list_local_zones|status)' % _W,
    re.escape(WIN_PROBE))]


def read_only_core(cmd):
    """The command without what discovery puts before it (PATH, timeout, sudo -n)."""
    c = cmd
    if c.startswith(PATH_PRE):
        c = c[len(PATH_PRE):]
    m = re.match(r'^timeout \d+ ', c)
    if m:
        c = c[m.end():]
    if c.startswith('sudo -n '):
        c = c[len('sudo -n '):]
    return c


def is_read_only(cmd):
    core = read_only_core(cmd)
    return any(r.match(core) for r in READ_ONLY)


class Discovery(object):
    """What runs on the DNS server: run(cmd, timeout) -> (rc, out, err) is the SSH
    session's run (check=False). Only commands of READ_ONLY are sent - anything
    else is refused here before it leaves (a bug, never the server's doing)."""
    LIMIT = 10                      # seconds a command may take there
    MOST_ZONES = 60                 # zones looked at more closely

    def __init__(self, run, cfg=None, step=None):
        self.run_fn = run
        self.cfg = dict(cfg or {})
        self.step = step or (lambda words, level='info': None)
        self.commands = []
        self.problems = []
        self.tools = {}
        self.root = False
        self.uid, self.gids, self.user = None, set(), ''
        self.sudo_ok = False
        self.has_timeout = False

    # -- the commands -----------------------------------------------------------------
    def sh(self, core, sudo=False, limit=True, plain=False):
        """(rc, out, err) of one read-only command; never raises for its exit.
        plain: as it is (Windows: no POSIX shell to set PATH in)."""
        cmd = core
        if sudo:
            cmd = 'sudo -n ' + cmd
        if limit and self.has_timeout:
            cmd = 'timeout %d %s' % (self.LIMIT, cmd)
        if not plain:
            cmd = PATH_PRE + cmd
        if not is_read_only(cmd):
            raise PluginError('discovery refused to send a command that is not on its read-only '
                              'list: %s' % core, retry=False)
        self.commands.append(cmd)
        try:
            rc, out, err = self.run_fn(cmd, self.LIMIT + 10)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            return 255, '', str(e)
        return rc, text_of(out), text_of(err)

    def priv(self, core):
        """A read that may need root: plainly, then through sudo -n when it can.
        (rc, out, err, through_sudo)."""
        rc, out, err = self.sh(core)
        if rc != 0 and not self.root and self.sudo_ok:
            rc2, out2, err2 = self.sh(core, sudo=True)
            if rc2 == 0:
                return rc2, out2, err2, True
        return rc, out, err, False

    def said(self, err, out=''):
        words = ' / '.join(x.strip() for x in (text_of(err) or text_of(out)).splitlines()
                           if x.strip())
        words = re.sub(r'secret\s+"[^"]*"', 'secret "…"', words)
        return words[:300] or 'no answer'

    def problem(self, words):
        if words not in self.problems:
            self.problems.append(words)

    # -- the whole -------------------------------------------------------------------
    def run(self):
        out = {'ok': False, 'os': '', 'user': '', 'root': False, 'sudo': False,
               'servers': [], 'server': '', 'version': '', 'flavour_suggested': '',
               'zones': [], 'keys': [], 'problems': self.problems, 'fields': {},
               'commands': self.commands}
        rc, os_name, err = self.sh('uname -s', limit=False)
        if rc != 0 or not os_name.strip() or os_name.strip().lower().startswith('windows'):
            return self.windows(out, err)
        out['os'] = os_name.strip()
        rc, uid, _e = self.sh('id -u', limit=False)
        _rc, user, _e = self.sh('id -un', limit=False)
        _rc, gids, _e = self.sh('id -G', limit=False)
        try:
            self.uid = int(uid.strip())
        except ValueError:
            self.uid = None
        self.gids = {int(g) for g in gids.split() if g.isdigit()}
        self.user = user.strip()
        self.root = self.uid == 0
        out.update(user=self.user, root=self.root)
        _rc, found, _e = self.sh(TOOLS_PROBE, limit=False)
        for line in found.splitlines():
            p = line.strip()
            if p.startswith('/'):
                self.tools.setdefault(os.path.basename(p), p)
        self.has_timeout = 'timeout' in self.tools
        if not self.root and 'sudo' in self.tools:
            rc, _o, _e = self.sh('true', sudo=True)
            self.sudo_ok = rc == 0
        out['sudo_works'] = self.root or self.sudo_ok
        active = set()
        if 'systemctl' in self.tools:
            rc, said, _e = self.sh(UNITS_PROBE)
            states = said.split()
            if len(states) == len(UNITS):
                active |= {u for u, s in zip(UNITS, states) if s == 'active'}
        if 'pgrep' in self.tools:
            _rc, said, _e = self.sh(PROCS_PROBE)
            procs = {ln.split(None, 1)[1].strip() for ln in said.splitlines()
                     if len(ln.split(None, 1)) == 2}
            for p, u in (('named', 'named'), ('pdns_server', 'pdns'), ('knotd', 'knot'),
                         ('nsd', 'nsd'), ('nsd: main', 'nsd'), ('dnsmasq', 'dnsmasq'),
                         ('unbound', 'unbound')):
                if p in procs:
                    active.add(u)
        if 'bind9' in active:
            active.add('named')
        servers, said = [], {}
        for unit, tools, fn in (('named', ('named', 'named-checkconf'), self.bind),
                                ('pdns', ('pdnsutil', 'pdns_server'), self.pdns),
                                ('knot', ('knotc',), self.knot),
                                ('nsd', ('nsd-checkconf',), self.nsd),
                                ('dnsmasq', ('dnsmasq',), self.dnsmasq),
                                ('unbound', ('unbound-control',), self.unbound)):
            if unit in active or any(t in self.tools for t in tools):
                n = len(self.problems)
                srv = fn(unit in active)
                said[id(srv)] = self.problems[n:]
                del self.problems[n:]
                servers.append(srv)
        out['servers'] = [{k: v for k, v in s.items() if k != 'fields'} for s in servers]
        if not servers:
            self.problem('no DNS server acme knows was found there (BIND, PowerDNS, Knot, NSD, '
                         'dnsmasq, Unbound) - set the fields by hand')
            out['ok'] = True
            return out

        def writable(s):
            return len([z for z in s.get('zones') or [] if z.get('flavour')])
        # the one with zones acme can write, then the one that runs, then the most zones
        best = sorted(servers, key=lambda s: (not writable(s), not s['active'],
                                              not s.get('flavour'), -writable(s)))[0]
        # what is said of a server only installed (not running, nothing of its own) is noise
        for s in servers:
            if s is best or s['active'] or writable(s):
                for p in said[id(s)]:
                    self.problem(p)
        out.update(server=best['server'], version=best.get('version', ''),
                   flavour_suggested=best.get('flavour', ''), zones=best.get('zones', []),
                   keys=best.get('keys', []), fields=dict(best.get('fields') or {}),
                   sudo=bool(best.get('fields', {}).get('sudo')))
        for s in servers:
            if s is not best and s['active']:
                self.problem('%s runs there too - acme suggests %s; another validation can use '
                             'the other one' % (s['server'], best['server']))
        out['ok'] = True
        return out

    # -- Windows ----------------------------------------------------------------------
    def windows(self, out, err):
        rc, said, err2 = self.sh(WIN_PROBE, limit=False, plain=True)
        if rc != 0:
            self.problem('the machine answered neither as Unix (uname) nor as Windows DNS '
                         '(Get-DnsServerZone): %s' % self.said(err2 or err))
            return out
        zones = []
        for line in text_of(said).splitlines():
            bits = [b.strip() for b in line.split(';')]
            if len(bits) < 5 or not bits[0]:
                continue
            if bits[3].lower() == 'true' or bits[4].lower() == 'true' or bits[0] == 'TrustAnchors':
                continue
            prim = bits[1].lower() == 'primary'
            zones.append({'name': D.norm(bits[0]), 'file': '', 'dynamic': True,
                          'type': bits[1].lower(), 'flavour': 'powershell' if prim else '',
                          'how_writable': 'PowerShell Add-DnsServerResourceRecord' if prim else
                          'a %s zone: written where it is primary' % bits[1].lower()})
        w = [z['name'] for z in zones if z['flavour']]
        out.update(ok=True, os='Windows', server='Windows DNS', flavour_suggested='powershell',
                   zones=zones, servers=[{'server': 'Windows DNS', 'active': True,
                                          'version': '', 'flavour': 'powershell'}],
                   fields={'flavour': 'powershell', 'zones': w})
        if len(w) == 1:
            out['fields']['zone'] = w[0]
        return out

    # -- BIND ------------------------------------------------------------------------
    def bind(self, active):
        s = {'server': 'BIND', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': '', 'fields': {}}
        if 'named' in self.tools:
            _rc, v, e = self.sh('named -v')
            m = re.search(r'BIND\s+(\S+)', v + e)
            s['version'] = m.group(1) if m else ''
        conf = str(self.cfg.get('named_conf') or '').strip()
        if conf:
            conf = safe_path(conf, 'named.conf')
        if 'named-checkconf' not in self.tools:
            self.problem('BIND: named-checkconf is not there - its zones cannot be read')
            return s
        rc, text, err, via = self.priv('named-checkconf -p' + (' ' + shq(conf) if conf else ''))
        if rc != 0:
            self.problem('BIND: named-checkconf -p could not read the configuration: %s%s' % (
                self.said(err, text), '' if self.root or self.sudo_ok else
                ' (sudo -n does not work for this account)'))
            return s
        if conf:
            s['fields']['named_conf'] = conf
        cf = parse_named_conf(text)
        s['keys'] = list(cf['keys'])
        direc = cf['directory'] or ''
        files = {}
        for z in cf['zones']:
            if z['type'] in ('primary', 'master') and z['file']:
                f = z['file'] if z['file'].startswith('/') else os.path.join(direc or '/', z['file'])
                files[z['name'], z['view']] = os.path.normpath(f)
        skeys = [cf['session_keyfile']] if cf['session_keyfile'] else [
            '/run/named/session.key', '/var/run/named/session.key']
        paths = []
        for f in list(files.values())[:self.MOST_ZONES]:
            paths += [f, f + '.jnl', os.path.dirname(f)]
        paths += skeys
        paths = [p for i, p in enumerate(paths) if p not in paths[:i] and PATH_RE.match(p)]
        seen = {}
        if paths:
            _rc, said, _e = self.sh('ls -lnd -- ' + ' '.join(shq(p) for p in paths),
                                    sudo=self.sudo_ok and not self.root)
            seen = parse_ls(said)
        skey = next((p for p in skeys if p in seen), '')
        skey_read = bool(skey) and may(seen.get(skey), self.uid, self.gids, 'r')
        # key files there (their key line only - never the secret)
        keyfiles = {}
        rc, said, _e, kvia = self.priv(KEYS_PROBE)
        for line in said.splitlines():
            m = re.match(r'^(/[^:]+):\s*key\s+"?([^"\s{]+)"?', line)
            if m and not m.group(1).endswith('session.key'):
                keyfiles.setdefault(m.group(2), m.group(1))
        for k in s['keys']:
            k['file'] = keyfiles.get(k['name'], '')
        for name, f in keyfiles.items():
            if not any(k['name'] == name for k in s['keys']):
                s['keys'].append({'name': name, 'algorithm': '', 'file': f})
        local, keyed, plain = [], [], []
        key_for = ''
        for z in cf['zones']:
            if z['name'] in ('', '.', 'localhost', '0.in-addr.arpa', '127.in-addr.arpa',
                             '255.in-addr.arpa') or z['type'] in ('hint', 'forward',
                                                                  'redirect', 'delegation-only'):
                continue
            f = files.get((z['name'], z['view']), '')
            entry = {'name': z['name'], 'file': f, 'view': z['view'], 'type': z['type'],
                     'dynamic': bool(z['policy'] or [a for a in z['allow_update']
                                                     if a.lower() != 'none']),
                     'journal': bool(f) and (f + '.jnl') in seen, 'flavour': '',
                     'how_writable': ''}
            if z['type'] not in ('primary', 'master'):
                entry['how_writable'] = 'a %s zone: written on its primary%s' % (
                    z['type'] or 'secondary', (' ' + ', '.join(z['primaries'])) if
                    z['primaries'] else '')
            elif 'local' in z['policy']:
                entry.update(flavour='nsupdate_local',
                             how_writable='nsupdate -l (update-policy local)')
                local.append(entry)
            elif zone_keys(z):
                k = zone_keys(z)[0]
                kf = keyfiles.get(k, '')
                entry.update(flavour='nsupdate_key', key=k,
                             how_writable='nsupdate -k with the key %s%s' % (
                                 k, (' (' + kf + ')') if kf else ' - its key file was not '
                                                                  'found'))
                keyed.append(entry)
                key_for = key_for or (k if kf else '')
            elif f:
                entry.update(flavour='bind_file', how_writable=(
                    'the zone file edited, then rndc %s' % (
                        'freeze/thaw (it is dynamic)' if entry['dynamic'] or entry['journal']
                        else 'reload')))
                plain.append(entry)
            else:
                entry['how_writable'] = 'no file and no updates: acme cannot write it'
            s['zones'].append(entry)
        fields = s['fields']
        if local:
            s['flavour'] = 'nsupdate_local'
            mine = local
            if cf['session_keyfile'] and cf['session_keyfile'] not in (
                    '/run/named/session.key', '/var/run/named/session.key'):
                fields['session_key'] = cf['session_keyfile']
            if not skey:
                self.problem('BIND: the session key (%s) is not there yet - named makes it when '
                             'it runs with a zone of update-policy local' % ' or '.join(skeys))
            fields['sudo'] = bool(not self.root and not skey_read and self.sudo_ok)
            if skey and not skey_read and not self.sudo_ok and not self.root:
                self.problem('BIND: %s cannot read the session key %s - put it in the group '
                             'of named (bind) or allow sudo -n nsupdate' % (self.user, skey))
        elif keyed and key_for:
            s['flavour'] = 'nsupdate_key'
            mine = [z for z in keyed if z.get('key') == key_for]
            fields['keyfile'] = keyfiles[key_for]
            fields['nsupdate_server'] = '127.0.0.1'
            fields['sudo'] = bool(not self.root and kvia)
        elif plain:
            s['flavour'] = 'bind_file'
            mine = plain
            fields['zone_files'] = ['%s %s' % (z['name'], z['file']) for z in plain]
            need = False
            for z in plain:
                d = seen.get(os.path.dirname(z['file']))
                if not (may(seen.get(z['file']), self.uid, self.gids, 'w') and
                        may(d, self.uid, self.gids, 'w')):
                    need = True
            fields['sudo'] = bool(need and not self.root)
            if need and not self.root and not self.sudo_ok:
                self.problem('BIND: %s cannot write the zone files and sudo -n does not work - '
                             'allow sudo (sh) or make them writable by its group' % self.user)
            if any(z['view'] for z in plain):
                self.problem('BIND: zones in views - rndc reload is told the zone name only')
        else:
            mine = []
            if keyed:
                self.problem('BIND: zones take updates signed by %s, but no key file of it '
                             'was found there - set the key file by hand' % ', '.join(
                                 sorted({z['key'] for z in keyed})))
                s['flavour'] = 'nsupdate_key'
                mine = keyed
                fields['nsupdate_server'] = '127.0.0.1'
        if s['flavour']:
            fields['flavour'] = s['flavour']
            names = [z['name'] for z in mine]
            fields['zones'] = names
            if len(names) == 1:
                fields['zone'] = names[0]
            other = [z['name'] for z in s['zones'] if z['flavour'] and
                     z['flavour'] != s['flavour']]
            if other:
                self.problem('BIND: %s written another way (%s) - another validation can do '
                             'those' % (', '.join(other[:10]), ', '.join(sorted(
                                 {z['flavour'] for z in s['zones'] if z['name'] in other}))))
        elif not s['zones']:
            self.problem('BIND: no zone of its own in the configuration')
        return s

    # -- PowerDNS ----------------------------------------------------------------------
    def pdns(self, active):
        s = {'server': 'PowerDNS', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': '', 'fields': {}}
        cdir = str(self.cfg.get('pdns_config_dir') or '').strip()
        if cdir:
            cdir = safe_path(cdir, 'configuration directory')
        if 'pdns_server' in self.tools:
            _rc, v, e = self.sh('pdns_server --version')
            m = re.search(r'PowerDNS Authoritative Server\s+(\S+)', v + e)
            s['version'] = m.group(1) if m else ''
        conf_files = ([cdir + '/pdns.conf'] if cdir else ['/etc/powerdns/pdns.conf',
                                                         '/etc/pdns/pdns.conf'])
        core = 'grep -hsE %s %s %s' % (PDNS_KEYS, ' '.join(shq(f) for f in conf_files),
                                       (shq(cdir) + '/pdns.d/*.conf') if cdir else
                                       '/etc/powerdns/pdns.d/*.conf')
        _rc, said, _e, _via = self.priv(core)
        api = {}
        for line in said.splitlines():
            k, _sep, v = line.partition('=')
            api[k.strip()] = v.strip()
        if 'pdnsutil' not in self.tools:
            self.problem('PowerDNS: pdnsutil is not there')
            return s
        pre = 'pdnsutil' + ((' --config-dir=' + shq(cdir)) if cdir else '')
        rc, said, err, via = self.priv(pre + ' list-all-zones')
        if rc != 0:
            self.problem('PowerDNS: pdnsutil list-all-zones did not work: %s' % self.said(err,
                                                                                    said))
            if api.get('api') in ('yes', 'true') and 'curl' in self.tools:
                s['flavour'] = 'pdns_api'
                s['fields'] = {'flavour': 'pdns_api', 'pdns_api_url': 'http://%s:%s' % (
                    api.get('webserver-address') or '127.0.0.1',
                    api.get('webserver-port') or '8081')}
                self.problem('PowerDNS: its HTTP API is on (api=yes) - set its API key')
            return s
        names = [D.norm(x) for x in said.split() if NAME_RE.match(D.norm(x) or '-')]
        for z in names:
            entry = {'name': z, 'file': '', 'dynamic': True, 'type': '', 'dnssec': None,
                     'flavour': 'pdnsutil', 'how_writable': 'pdnsutil add-record / '
                                                            'replace-rrset'}
            s['zones'].append(entry)
        for entry in s['zones'][:20]:
            rc, said, _e = self.sh(pre + ' show-zone ' + shq(entry['name']), sudo=via)
            if rc == 0:
                entry['dnssec'] = 'not actively secured' not in said
                m = re.search(r'This is a (\w+) zone', said)
                entry['type'] = (m.group(1).lower() if m else '')
                if entry['type'] in ('slave', 'secondary', 'consumer'):
                    entry.update(flavour='', how_writable='a secondary zone: written on its '
                                                          'primary')
        s['flavour'] = 'pdnsutil'
        mine = [z['name'] for z in s['zones'] if z['flavour']]
        s['fields'] = {'flavour': 'pdnsutil', 'sudo': bool(via), 'zones': mine,
                       'pdns_rectify': True}
        if cdir:
            s['fields']['pdns_config_dir'] = cdir
        if len(mine) == 1:
            s['fields']['zone'] = mine[0]
        if api.get('api') in ('yes', 'true'):
            s['api'] = 'http://%s:%s' % (api.get('webserver-address') or '127.0.0.1',
                                         api.get('webserver-port') or '8081')
        if not names:
            self.problem('PowerDNS: it has no zones yet')
        return s

    # -- Knot ------------------------------------------------------------------------
    def knot(self, active):
        s = {'server': 'Knot DNS', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': '', 'fields': {}}
        pre = 'knotc'
        for k, opt in (('knot_conf', '-c'), ('knot_socket', '-s')):
            v = str(self.cfg.get(k) or '').strip()
            if v:
                pre += ' %s %s' % (opt, shq(safe_path(v)))
                s['fields'][k] = v
        _rc, v, e = self.sh(pre + ' -V')
        m = re.search(r'version\s+(\S+)', v + e)
        s['version'] = m.group(1) if m else ''
        rc, said, err, via = self.priv(pre + ' zone-status')
        zones = []
        if rc == 0:
            for line in said.splitlines():
                m = re.match(r'^\[([^\]]+)\]\s*(.*)$', line.strip())
                if m:
                    role = re.search(r'role:\s*(\w+)', m.group(2))
                    zones.append((D.norm(m.group(1)), role.group(1) if role else ''))
        else:
            rc, said, err2, via = self.priv(pre + ' conf-read zone.domain')
            if rc != 0:
                self.problem('Knot: knotc could not ask the server (%s) - is knotd running, '
                             'and may this account use its control socket?' % self.said(err,
                                                                                     said))
                return s
            for line in said.splitlines():
                m = re.match(r'^zone\.domain\s*=\s*(.*)$', line.strip())
                if m:
                    zones += [(D.norm(x), '') for x in m.group(1).split()]
            self.problem('Knot: knotd does not answer knotc - the zones are those of its '
                         'configuration')
        for name, role in zones:
            ok = role not in ('slave', 'secondary')
            s['zones'].append({'name': name, 'file': '', 'dynamic': True, 'type': role,
                               'flavour': 'knot' if ok else '',
                               'how_writable': 'knotc zone-begin / zone-set / zone-commit' if ok
                               else 'a secondary zone: written on its primary'})
        mine = [z['name'] for z in s['zones'] if z['flavour']]
        s['flavour'] = 'knot'
        s['fields'].update(flavour='knot', sudo=bool(via), zones=mine)
        if len(mine) == 1:
            s['fields']['zone'] = mine[0]
        return s

    # -- NSD -------------------------------------------------------------------------
    def nsd(self, active):
        s = {'server': 'NSD', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': '', 'fields': {}}
        conf = safe_path(str(self.cfg.get('nsd_conf') or '').strip() or '/etc/nsd/nsd.conf',
                         'nsd.conf')
        if 'nsd' in self.tools:
            _rc, v, e = self.sh('nsd -v')
            m = re.search(r'NSD version\s+(\S+)', v + e)
            s['version'] = m.group(1) if m else ''
        if 'nsd-checkconf' not in self.tools:
            self.problem('NSD: nsd-checkconf is not there - its zones cannot be read')
            return s
        rc, said, err, via = self.priv('nsd-checkconf -o zones ' + shq(conf))
        if rc != 0:
            self.problem('NSD: nsd-checkconf could not read %s: %s' % (conf, self.said(err,
                                                                                 said)))
            return s
        if conf != '/etc/nsd/nsd.conf':
            s['fields']['nsd_conf'] = conf
        _rc, zdir, _e = self.sh('nsd-checkconf -o zonesdir ' + shq(conf), sudo=via)
        zdir = zdir.strip() or '/etc/nsd'
        names = [D.norm(x) for x in said.split() if NAME_RE.match(D.norm(x) or '-')]
        files = {}
        for z in names[:self.MOST_ZONES]:
            rc, f, _e = self.sh('nsd-checkconf -z %s -o zonefile %s' % (shq(z), shq(conf)),
                                sudo=via)
            f = f.strip().replace('%s', z)
            if rc == 0 and f:
                files[z] = os.path.normpath(f if f.startswith('/') else os.path.join(zdir, f))
            rc, xfr, _e = self.sh('nsd-checkconf -z %s -o request-xfr %s' % (shq(z), shq(conf)),
                                  sudo=via)
            if rc == 0 and xfr.strip():
                files[z] = ('secondary', xfr.strip().split()[0])
        paths = []
        for f in files.values():
            if isinstance(f, str):
                paths += [f, os.path.dirname(f)]
        paths = [p for i, p in enumerate(paths) if p not in paths[:i] and PATH_RE.match(p)]
        seen = {}
        if paths:
            _rc, out, _e = self.sh('ls -lnd -- ' + ' '.join(shq(p) for p in paths),
                                   sudo=self.sudo_ok and not self.root)
            seen = parse_ls(out)
        plain, need = [], False
        for z in names:
            f = files.get(z, '')
            if isinstance(f, tuple):
                s['zones'].append({'name': z, 'file': '', 'dynamic': False, 'type': 'secondary',
                                   'flavour': '', 'how_writable': 'a secondary zone: written '
                                                                  'on its primary %s' % f[1]})
                continue
            entry = {'name': z, 'file': f, 'dynamic': False, 'type': 'primary',
                     'flavour': 'nsd' if f else '',
                     'how_writable': 'the zone file edited, then nsd-control reload' if f else
                     'no zone file known'}
            if f and f not in seen:
                entry['how_writable'] += ' (the file is not there yet)'
            s['zones'].append(entry)
            if f:
                plain.append(entry)
                if not (may(seen.get(f), self.uid, self.gids, 'w') and
                        may(seen.get(os.path.dirname(f)), self.uid, self.gids, 'w')):
                    need = True
        s['flavour'] = 'nsd'
        s['fields'].update(flavour='nsd', sudo=bool((need or via) and not self.root),
                           zones=[z['name'] for z in plain],
                           zone_files=['%s %s' % (z['name'], z['file']) for z in plain])
        if len(plain) == 1:
            s['fields']['zone'] = plain[0]['name']
        return s

    # -- dnsmasq ------------------------------------------------------------------------
    def dnsmasq(self, active):
        s = {'server': 'dnsmasq', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': 'dnsmasq', 'fields': {'flavour': 'dnsmasq'}}
        if 'dnsmasq' in self.tools:
            _rc, v, e = self.sh('dnsmasq --version')
            m = re.search(r'Dnsmasq version\s+(\S+)', v + e)
            s['version'] = m.group(1) if m else ''
        conf = str(self.cfg.get('dnsmasq_conf') or '').strip()
        files = [safe_path(conf)] if conf else ['/etc/dnsmasq.conf']
        _rc, said, _e, via = self.priv('grep -hsE %s %s /etc/dnsmasq.d/*.conf' % (
            DNSMASQ_KEYS, ' '.join(shq(f) for f in files)))
        zones, dirs = [], []
        for line in said.splitlines():
            k, _sep, v = line.strip().partition('=')
            if k == 'local':
                m = re.match(r'^/([^/]+)/', v)
                if m:
                    zones.append(D.norm(m.group(1)))
            elif k in ('auth-zone', 'domain'):
                zones.append(D.norm(v.split(',')[0]))
            elif k == 'conf-dir':
                dirs.append(v.split(',')[0].rstrip('/'))
        zones = [z for i, z in enumerate(zones) if z and z not in zones[:i] and NAME_RE.match(z)]
        target = str(self.cfg.get('dnsmasq_file') or '').strip() or \
            '/etc/dnsmasq.d/acme-challenge.conf'
        tdir = os.path.dirname(target)
        _rc, out, _e = self.sh('ls -lnd -- %s' % shq(tdir))
        seen = parse_ls(out)
        if tdir not in seen:
            self.problem('dnsmasq: %s is not there - make it, and have dnsmasq read it '
                         '(conf-dir=%s/,*.conf)' % (tdir, tdir))
        elif dirs and tdir not in dirs and tdir != '/etc/dnsmasq.d':
            self.problem('dnsmasq: its configuration names no conf-dir=%s' % tdir)
        for z in zones:
            s['zones'].append({'name': z, 'file': target, 'dynamic': False, 'type': 'local',
                               'flavour': 'dnsmasq', 'how_writable': 'txt-record in %s, then a '
                                                                     'restart' % target})
        s['fields'].update(zones=zones, sudo=bool(not self.root and not may(
            seen.get(tdir), self.uid, self.gids, 'w')))
        if len(zones) == 1:
            s['fields']['zone'] = zones[0]
        self.problem('dnsmasq: it reads txt-record only when it starts - acme restarts it '
                     '(systemctl restart dnsmasq) for each change')
        return s

    # -- Unbound ------------------------------------------------------------------------
    DEFAULT_LOCAL = ('localhost', 'test', 'invalid', 'onion', 'local', 'home.arpa',
                     'resolver.arpa', 'service.arpa')

    def unbound(self, active):
        s = {'server': 'Unbound', 'active': active, 'version': '', 'zones': [], 'keys': [],
             'flavour': '', 'fields': {}}
        if 'unbound' in self.tools:
            _rc, v, e = self.sh('unbound -V')
            m = re.search(r'Version\s+(\S+)', v + e)
            s['version'] = m.group(1) if m else ''
        pre = 'unbound-control'
        conf = str(self.cfg.get('unbound_conf') or '').strip()
        if conf:
            pre += ' -c ' + shq(safe_path(conf))
            s['fields']['unbound_conf'] = conf
        rc, said, err, via = self.priv(pre + ' list_local_zones')
        if rc != 0:
            self.problem('Unbound: unbound-control could not ask it (%s) - remote-control '
                         'enabled, and may this account use it?' % self.said(err, said))
            return s
        for line in said.splitlines():
            bits = line.split()
            if len(bits) < 2:
                continue
            z = D.norm(bits[0])
            if not z or z in self.DEFAULT_LOCAL or z.endswith('.arpa') or not NAME_RE.match(z):
                continue
            s['zones'].append({'name': z, 'file': '', 'dynamic': True, 'type': bits[1],
                               'flavour': 'unbound',
                               'how_writable': 'unbound-control local_data (in memory)'})
        mine = [z['name'] for z in s['zones']]
        s['flavour'] = 'unbound'
        s['fields'].update(flavour='unbound', sudo=bool(via), zones=mine)
        if len(mine) == 1:
            s['fields']['zone'] = mine[0]
        self.problem('Unbound: a resolver - the CA asks the zone\'s authoritative servers; '
                     'local data helps only where Unbound is the one asked (an internal CA)')
        return s
