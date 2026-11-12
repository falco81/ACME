# -*- coding: utf-8 -*-
"""The words of the pages' translation (web/lang/<code>.json) for what the daemon writes
itself in a language - the report and the mails (1.0.80): the events, alerts and
certificate lines are kept in English and were put into a Czech report as they were.

The same rules as web/assets/i18n.js, in short: a whole text first, then the pattern with
the most words of its own (its slots translated again, two levels deep), a number's word
by `{0:one|two to four|five and more}`; a "weak" pattern (hardly any words of its own)
takes no slot that is a sentence. What is not known stays as it is."""
from __future__ import annotations

import json
import os
import re
import threading

_LOCK = threading.Lock()
_PACKS = {}
DEEP = 2


def _places(code):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [os.path.join(here, 'web', 'lang', '%s.json' % code),
            os.path.join('/var/www/acme/lang', '%s.json' % code)]


def _fold(s):
    return re.sub(r'\s+', ' ', str(s)).strip()


def _compile(source):
    across = bool(re.search(r'\s[·•|—]\s', source)) or \
        len(re.sub(r'\{\d+\}', '', source)) >= 25
    anyp = r'(.*?)' if across else r'((?:(?!\s[·•|—]\s).)*?)'
    bits = re.split(r'(\{\d+\})', source)
    slots, body = [], []
    for i, bit in enumerate(bits):
        m = re.match(r'^\{(\d+)\}$', bit)
        if not m:
            body.append(re.escape(bit))
            continue
        slots.append(int(m.group(1)))
        before = bits[i - 1] if i > 0 else ''
        after = bits[i + 1] if i < len(bits) - 1 else ''
        body.append((r'(?![A-Za-z])' if re.search(r'[A-Za-z]$', before) else '') + anyp +
                    (r'(?<![A-Za-z])' if re.match(r'^[A-Za-z]', after) else ''))
    try:
        rx = re.compile('^' + ''.join(body) + '$', re.S)
    except re.error:
        return None
    own = len(re.sub(r'\{\d+\}', '', source))
    words = re.findall(r'[A-Za-z]{2,}', re.sub(r'\{\d+\}', ' ', source))
    lit = max(re.split(r'\{\d+\}', source), key=len)
    return {'re': rx, 'slots': slots, 'own': own, 'lit': lit,
            'lead': not re.match(r'^\{\d+\}', source),
            'weak': len(words) < 2 or len(re.sub(r'\{\d+\}', '', source).strip()) < 10}


def pack(code):
    """{exact: {source: text}, pats: [compiled]} for a language, or None."""
    code = re.sub(r'[^a-z]', '', str(code or ''))[:5]
    if not code or code == 'en':
        return None
    with _LOCK:
        if code in _PACKS:
            return _PACKS[code]
        got = None
        for p in _places(code):
            try:
                with open(p, encoding='utf-8') as f:
                    raw = json.load(f)
                break
            except (OSError, ValueError):
                raw = None
        if isinstance(raw, dict):
            exact, pats = {}, []
            for v in (raw.get('strings') or {}).values():
                if isinstance(v, dict) and v.get('source') and v.get('text'):
                    exact[_fold(v['source'])] = v['text']
            for v in (raw.get('patterns') or {}).values():
                if isinstance(v, dict) and v.get('source') and v.get('text'):
                    c = _compile(v['source'])
                    if c:
                        c['text'] = v['text']
                        pats.append(c)
            got = {'exact': exact, 'pats': pats}
        _PACKS[code] = got
        return got


def _plural(text, slots, m):
    def one(mm):
        n, forms = int(mm.group(1)), mm.group(2).split('|')
        if n not in slots:
            return mm.group(0)
        said = re.sub(r'[\s, ]', '', m.group(slots.index(n) + 1) or '')
        if not re.match(r'^-?\d+$', said):
            return forms[-1]
        count = abs(int(said))
        if len(forms) == 2:
            return forms[0] if count == 1 else forms[1]
        if count == 1:
            return forms[0]
        if 2 <= count <= 4:
            return forms[1]
        return forms[2] if len(forms) > 2 else forms[-1]
    return re.sub(r'\{(\d+):([^}]*)\}', one, text)


def _wordy(m, p, depth):
    for i in range(1, len(m.groups()) + 1):
        v = m.group(i) or ''
        if re.search(r'\S: \S', v) and (depth >= DEEP or _work(v, p, depth + 1) is None):
            return True                                 # a sentence of its own
        if not re.search(r'(^|\s)[A-Za-z]{2,}[,;:]?\s+[A-Za-z]{2,}(\s|$|[.,;:])', v):
            continue
        if not re.search(r'(^|\s)[a-z][A-Za-z]*[,;:]?(\s|$)', v) and re.match(r'^[\sA-Z0-9]', v):
            continue                                    # a name of capitalised words
        if depth < DEEP and _work(v, p, depth + 1) is not None:
            continue
        return True
    return False


def _work(s, p, depth=0):
    key = _fold(s)
    if not key or not re.search(r'[A-Za-z]{2}', key):
        return None
    hit = p['exact'].get(key)
    if hit is not None:
        return hit
    if re.match(r'^[A-Z][a-z]', key) and ' ' in key:
        hit = p['exact'].get(key[0].lower() + key[1:])
        if hit:
            return hit[0].upper() + hit[1:]
    best, best_own = None, -1
    for c in p['pats']:
        if c['lit'] and c['lit'] not in key:
            continue
        m = c['re'].match(key)
        if not m or (c['weak'] and _wordy(m, p, depth)):
            continue
        own = (1000 if c['lead'] else 0) + c['own']
        if own > best_own:
            best, best_own = (c, m), own
    # a node's (or a place's) name, a colon and a sentence of its own
    if depth < DEEP and (not best or (not best[0]['lead'] and ': ' in (best[1].group(1) or ''))):
        nm = re.match(r'^([A-Za-z0-9][\w.:/\[\]-]{0,80}): (.*[A-Za-z]{2}.*)$', key)
        if nm and re.search(r'[0-9.:/-]', nm.group(1)):
            got = _work(nm.group(2), p, depth + 1)
            if got is not None:
                return nm.group(1) + ': ' + got
    if not best:
        return None
    c, m = best

    def slot(mm):
        n = int(mm.group(1))
        if n not in c['slots']:
            return mm.group(0)
        v = m.group(c['slots'].index(n) + 1) or ''
        if depth < DEEP:
            got = _work(v, p, depth + 1)
            if got is not None:
                return got
        return v
    return re.sub(r'\{(\d+)\}', slot, _plural(c['text'], c['slots'], m))


def tr(s, code):
    """`s` in the language `code`, or `s` as it is."""
    p = pack(code)
    if not p or not s:
        return s
    try:
        got = _work(str(s), p)
    except Exception:                                   # noqa: BLE001
        got = None
    return s if got is None else got
