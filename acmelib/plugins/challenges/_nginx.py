# -*- coding: utf-8 -*-
"""The server blocks of an nginx that already answers port 80 (nginx -T read
over SSH): which listen on port 80, and the same files with one line put at
the top of each of them -

    include /etc/nginx/snippets/acme-challenge.conf;   # acme

The snippet (snippet_text) starts with `rewrite ... break`: at the server
level nginx runs rewrite, return and if in their order, so a `return 301` or
an `if ($host ...) { return ... }` below it (certbot writes those) would
answer before any location is looked for. `break` ends that list for the
challenge paths only; then its own `location ^~` serves the file. Everything
else in the block goes on exactly as before.

Parsing is of nginx's own grammar, enough for this: words, quoted strings,
comments, `;`, `{` and `}`.
"""
from __future__ import annotations

import re

MARK = '# acme'
FILE_RE = re.compile(r'^# configuration file (.+?):\s*$')


def split_dump(text):
    """nginx -T: {path: content} in the order they came."""
    out, cur, buf = {}, None, []
    for line in str(text or '').splitlines(True):
        m = FILE_RE.match(line.rstrip('\n'))
        if m:
            if cur is not None:
                out[cur] = ''.join(buf)
            cur, buf = m.group(1), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = ''.join(buf)
    return out


def tokens(text):
    """(kind, value, start, end): word | ; | { | } - comments left out."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j
        elif c in ';{}':
            yield c, c, i, i + 1
            i += 1
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == '\\' else 1
            yield 'word', text[i + 1:j], i, min(j + 1, n)
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ';{}"\'' and \
                    not (text[j] == '#' and j > i and text[j - 1].isspace()):
                if text[j] == '\\':
                    j += 1
                j += 1
            yield 'word', text[i:j], i, j
            i = j


def server_blocks(text):
    """[{'open': index after '{', 'close': index of '}', 'listen': [[args]],
    'parent': name of the block around it or ''}] of every `server { }`."""
    out, stack, words = [], [], []
    for kind, val, a, b in tokens(text):
        if kind == 'word':
            words.append(val)
        elif kind == ';':
            if stack and stack[-1].get('server') is not None and len(stack) == stack[-1]['depth'] \
                    and words and words[0] == 'listen':
                stack[-1]['server']['listen'].append(words[1:])
            if stack and stack[-1].get('server') is not None and words and \
                    len(stack) == stack[-1]['depth']:
                stack[-1]['server']['directives'].append(words[0])
            words = []
        elif kind == '{':
            name = words[0] if words else ''
            parent = stack[-1]['name'] if stack else ''
            entry = {'name': name, 'depth': len(stack) + 1, 'server': None}
            if name == 'server' and len(words) == 1 and parent in ('', 'http'):
                entry['server'] = {'open': b, 'close': None, 'listen': [], 'parent': parent,
                                   'directives': [], 'locations': []}
                out.append(entry['server'])
            elif name == 'location' and stack and stack[-1].get('server') is not None:
                stack[-1]['server']['locations'].append(' '.join(words[1:]))
            stack.append(entry)
            words = []
        elif kind == '}':
            if stack:
                top = stack.pop()
                if top.get('server') is not None and top['name'] == 'server':
                    top['server']['close'] = a
            words = []
    return [s for s in out if s['close'] is not None]


def on_port_80(block):
    """Does this server block answer plain HTTP on port 80? (No listen: *:80.)"""
    if not block['listen']:
        return True
    for args in block['listen']:
        if not args:
            continue
        addr = args[0]
        rest = [x.lower() for x in args[1:]]
        if 'ssl' in rest or 'quic' in rest or 'udp' in rest:
            continue
        port = addr.rsplit(':', 1)[-1] if (':' in addr and not addr.endswith(']')) else addr
        if addr.startswith('unix:'):
            continue
        if port == '80':
            return True
    return False


def has_challenge(block):
    return any('acme-challenge' in loc for loc in block['locations'])


def patch(text, include_line):
    """The file with the include put at the top of each of its port-80 server
    blocks that has none: (new text, [patched], [left: (what, why)])."""
    blocks = [b for b in server_blocks(text) if on_port_80(b)]
    done, left, out, last = [], [], [], 0
    for blk in blocks:
        body = text[blk['open']:blk['close']]
        label = _label(text, blk)
        if include_line.split('#')[0].strip().rstrip(';') in body:
            continue
        if has_challenge(blk):
            left.append((label, 'has a location for /.well-known/acme-challenge/ of its own - '
                                'left as it is'))
            continue
        out.append(text[last:blk['open']])
        out.append('\n    %s\n' % include_line)
        last = blk['open']
        done.append(label)
    out.append(text[last:])
    return ''.join(out), done, left


def names_of(text, blk):
    """The server_name words of a block (lower case)."""
    m = re.search(r'(?m)^\s*server_name\s+([^;]+);', text[blk['open']:blk['close']])
    return [x.lower() for x in m.group(1).split()] if m else []


def port80_names(files, skip=()):
    """{name: file} of every server_name a port-80 block of these files answers for."""
    out = {}
    for path, text in files.items():
        if path in skip:
            continue
        for b in server_blocks(text):
            if on_port_80(b):
                for n in names_of(text, b):
                    out.setdefault(n, path)
    return out


def _label(text, blk):
    m = re.search(r'(?m)^\s*server_name\s+([^;]+);', text[blk['open']:blk['close']])
    names = m.group(1).split() if m else ['(no server_name)']
    return ' '.join(names[:4]) + (' …' if len(names) > 4 else '')


def snippet_text(docroot, pki=True):
    """The file the include points at. `docroot` is the folder that holds
    .well-known/ (the tokens' folder without /.well-known/acme-challenge):
    `root`, not `alias` - nginx refuses alias where the URI was rewritten."""
    lines = ['# acme: the answers to HTTP-01, included at the top of every port-80 server',
             '# block (written by acme, "Prepare the hosts" - docs/validation.md).',
             '# The rewrite ... break ends the server-level rewrite/return/if of the block',
             '# for these paths only, so the location below answers them.',
             'rewrite ^(/\\.well-known/acme-challenge/.*)$ $1 break;']
    if pki:
        lines.append('rewrite ^(/\\.well-known/pki-validation/.*)$ $1 break;')
    lines += ['location ^~ /.well-known/acme-challenge/ {',
              '    root %s;' % docroot,
              '    default_type text/plain;',
              '    autoindex off;',
              '}']
    if pki:
        lines += ['location ^~ /.well-known/pki-validation/ {',
                  '    root %s;' % docroot,
                  '    default_type text/plain;',
                  '    autoindex off;',
                  '}']
    return '\n'.join(lines) + '\n'
