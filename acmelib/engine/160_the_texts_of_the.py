# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The texts of the messages, edited on the pages (1.0.103)
# ---------------------------------------------------------------------------
# Every word a person gets from this server - the mails of a code, the SMS,
# and whatever a module mails - in both languages, as it is written in the
# defaults (TEXT_GROUPS), unless changed in Settings → Message texts. What is
# changed is kept in the database (meta texts:<message>:<lang>, the fields
# changed only), so both nodes of a cluster send the same words; each node
# reads them again within seconds. Put back to the default, a text is exactly
# as it was before it was changed.
#
# The registry is TEXT_MESSAGES, a list a module appends its own messages to,
# with their default words in TEXT_GROUPS[group][lang] (and placeholders of its
# own in TEXT_PLACEHOLDERS and TEXT_SAMPLES):
#   {'id': 'cert_expiring', 'kind': 'mail' | 'sms' | 'text', 'group': 'certs',
#    'title': ..., 'short': ..., 'says': ...,
#    'fields': [(key, 'line' | 'rich' | 'text', label, (placeholders...), where)],
#    'render': fn(words, samples, lang) -> {'html', 'subject', 'text'}  (a mail's preview)}
# texts_for(group, lang) gives the words to send with, changes and all.
import html.parser as _html_parser

TEXT_MESSAGES = [
    {'id': 'verify_mail', 'kind': 'mail', 'group': 'code', 'purpose': 'verify',
     'title': 'Checking an address',
     'says': 'Sent to check an address something will be mailed to.',
     'fields': [
         ('verify_subject', 'line', 'Subject', ('code', 'minutes', 'site'), 'subject'),
         ('h_v_title', 'line', 'The band at the top', ('site',), 'layout'),
         ('h_v_hello', 'rich', 'Greeting', ('name',), 'layout'),
         ('h_v_lede', 'rich', 'What it is', ('account',), 'layout'),
         ('h_v_facts', 'rich', 'Under the code', ('minutes',), 'layout'),
         ('h_v_note', 'rich', 'The note', (), 'layout'),
         ('h_v_foot', 'rich', 'The foot', ('site',), 'layout'),
         ('h_v_hello_anon', 'rich', 'Greeting when the name is not known', (), 'other'),
         ('h_v_lede_anon', 'rich', 'What it is when the account is not known', (), 'other'),
         ('verify_body', 'text', 'The plain text version', ('code', 'minutes', 'site'), 'plain'),
     ]},
    {'id': 'sms_verify', 'kind': 'sms', 'group': 'code', 'title': 'Checking a number',
     'says': 'Sent to check a number something will be sent to by SMS.',
     'fields': [('sms_verify', 'text', 'The SMS', ('code', 'minutes', 'site'), 'sms')]},
    # The administration's second step (1.0.127): its own words.
    {'id': 'admin_mail', 'short': 'The sign-in code by mail', 'kind': 'mail', 'group': 'code', 'purpose': 'admin',
     'title': 'The administration: a sign-in code by mail',
     'says': 'Sent when an administrator signs in to these pages with the second step by mail.',
     'fields': [
         ('admin_subject', 'line', 'Subject', ('code', 'minutes', 'site'), 'subject'),
         ('h_a_title', 'line', 'The band at the top', ('site',), 'layout'),
         ('h_a_hello', 'rich', 'Greeting', ('name',), 'layout'),
         ('h_a_lede', 'rich', 'What it is', ('account',), 'layout'),
         ('h_a_facts', 'rich', 'Under the code', ('minutes',), 'layout'),
         ('h_a_warn', 'rich', 'The warning', (), 'layout'),
         ('h_a_foot', 'rich', 'The foot', ('site',), 'layout'),
         ('h_a_hello_anon', 'rich', 'Greeting when the name is not known', (), 'other'),
         ('h_a_lede_anon', 'rich', 'What it is when the account is not known', (), 'other'),
         ('admin_body', 'text', 'The plain text version', ('code', 'minutes', 'site'), 'plain'),
     ]},
    {'id': 'admin_verify_mail', 'short': 'Checking an address', 'kind': 'mail', 'group': 'code', 'purpose': 'admin_verify',
     'title': 'The administration: checking an address',
     'says': 'Sent when an administrator sets up the second step by mail, to check the address.',
     'fields': [
         ('admin_verify_subject', 'line', 'Subject', ('code', 'minutes', 'site'), 'subject'),
         ('h_av_title', 'line', 'The band at the top', ('site',), 'layout'),
         ('h_av_hello', 'rich', 'Greeting', ('name',), 'layout'),
         ('h_av_lede', 'rich', 'What it is', ('account',), 'layout'),
         ('h_av_facts', 'rich', 'Under the code', ('minutes',), 'layout'),
         ('h_av_note', 'rich', 'The note', (), 'layout'),
         ('h_av_foot', 'rich', 'The foot', ('site',), 'layout'),
         ('h_av_hello_anon', 'rich', 'Greeting when the name is not known', (), 'other'),
         ('h_av_lede_anon', 'rich', 'What it is when the account is not known', (), 'other'),
         ('admin_verify_body', 'text', 'The plain text version', ('code', 'minutes', 'site'),
          'plain'),
     ]},
    {'id': 'admin_sms', 'short': 'The sign-in code by SMS', 'kind': 'sms', 'group': 'code',
     'title': 'The administration: a sign-in code by SMS',
     'says': 'Sent when an administrator signs in to these pages with the second step by SMS.',
     'fields': [('admin_sms', 'text', 'The SMS', ('code', 'minutes', 'site'), 'sms')]},
    {'id': 'admin_sms_verify', 'short': 'Checking a number', 'kind': 'sms', 'group': 'code',
     'title': 'The administration: checking a number',
     'says': 'Sent when an administrator sets up the second step by SMS, to check the number.',
     'fields': [('admin_sms_verify', 'text', 'The SMS', ('code', 'minutes', 'site'), 'sms')]},
    # Signing in over SSH to the nodes (1.0.40, as otp 1.0.181): an SSH token by mail or SMS.
    {'id': 'ssh_mail', 'short': 'The sign-in code by mail', 'kind': 'mail', 'group': 'code', 'purpose': 'ssh',
     'title': 'SSH: a sign-in code by mail',
     'says': 'Sent when somebody signs in over SSH to the nodes with an SSH token by mail.',
     'fields': [
         ('ssh_subject', 'line', 'Subject', ('code', 'minutes', 'site'), 'subject'),
         ('h_s_title', 'line', 'The band at the top', ('site',), 'layout'),
         ('h_s_hello', 'rich', 'Greeting', ('name',), 'layout'),
         ('h_s_lede', 'rich', 'What it is', ('account',), 'layout'),
         ('h_s_facts', 'rich', 'Under the code', ('minutes',), 'layout'),
         ('h_s_warn', 'rich', 'The warning', (), 'layout'),
         ('h_s_foot', 'rich', 'The foot', ('site',), 'layout'),
         ('h_s_hello_anon', 'rich', 'Greeting when the name is not known', (), 'other'),
         ('h_s_lede_anon', 'rich', 'What it is when the account is not known', (), 'other'),
         ('ssh_body', 'text', 'The plain text version', ('code', 'minutes', 'site'), 'plain'),
     ]},
    {'id': 'ssh_sms', 'short': 'The sign-in code by SMS', 'kind': 'sms', 'group': 'code',
     'title': 'SSH: a sign-in code by SMS',
     'says': 'Sent when somebody signs in over SSH to the nodes with an SSH token by SMS.',
     'fields': [('ssh_sms', 'text', 'The SMS', ('code', 'minutes', 'site'), 'sms')]},
]
TEXT_LANGS = ('cs', 'en')
TEXT_PLACEHOLDERS = {
    'code': 'the code', 'minutes': 'minutes it is good for', 'site': 'the server’s name',
    'name': 'the person’s name', 'account': 'the account', 'dest': 'where it was sent',
    'by': 'who did it'}
# A sample value of each placeholder a module adds, for the previews.
TEXT_SAMPLES = {}
# The default words of each group of messages: {group: {lang: {key: words}}}.
TEXT_GROUPS = {'code': CODE_TEXTS}
TEXT_MOST = {'line': 300, 'rich': 3000, 'text': 4000}
TEXT_CACHE = {}
TEXT_CACHE_S = 5.0
TEXT_LOCK = threading.Lock()


def text_message(mid):
    return next((m for m in TEXT_MESSAGES if m['id'] == mid), None)


def text_defaults(group, lang):
    words = TEXT_GROUPS.get(group) or {}
    return dict(words.get(lang) or words.get('cs') or words.get('en') or {})


def text_saved(store, mid, lang):
    """What is saved for one message in one language: {'f': {...}, 'at', 'by'}."""
    try:
        got = json.loads(store.get_meta('texts:%s:%s' % (mid, lang)) or 'null')
    except ValueError:
        got = None
    if not isinstance(got, dict) or not isinstance(got.get('f'), dict):
        return {'f': {}, 'at': None, 'by': None}
    return got


def texts_for(group, lang):
    """The words of one group (code: the mails and the SMS of codes; a
    module's own) in one language - the defaults
    with what was changed on the pages over them. Read again every few
    seconds; if the database cannot be asked, the defaults, never nothing."""
    lang = lang if lang in TEXT_LANGS else 'cs'
    key = (group, lang)
    now = time.time()
    with TEXT_LOCK:
        got = TEXT_CACHE.get(key)
        if got and now - got[0] < TEXT_CACHE_S:
            return dict(got[1])
    words = text_defaults(group, lang)
    store = HA_STORE.get('store')
    if store is not None:
        try:
            for m in TEXT_MESSAGES:
                if m['group'] != group:
                    continue
                keys = {f[0] for f in m['fields']}
                for k, v in text_saved(store, m['id'], lang)['f'].items():
                    if k in keys and isinstance(v, str):
                        words[k] = v
        except Exception as e:                          # noqa: BLE001
            log_sparing('texts', 'the message texts could not be read - the defaults are used: '
                        '%s' % str(e).split('\n')[0][:200], 'warn')
            return text_defaults(group, lang)
    with TEXT_LOCK:
        TEXT_CACHE[key] = (now, words)
    return dict(words)


def texts_forget():
    with TEXT_LOCK:
        TEXT_CACHE.clear()


# ---- what may be written ---------------------------------------------------------
class _RichClean(_html_parser.HTMLParser):
    """HTML of a text in a mail, kept to what mail programs show alike: bold,
    italic, underline, a colour, a link, a line break. Everything else goes,
    its text stays."""
    COLOR = re.compile(r'\s*(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}|rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,'
                       r'\s*\d{1,3}\s*\))\s*\Z')

    def __init__(self):
        _html_parser.HTMLParser.__init__(self, convert_charrefs=True)
        self.out = []
        self.stack = []

    @staticmethod
    def _style(attrs):
        st = {}
        for part in str(dict(attrs).get('style') or '').split(';'):
            k, _, v = part.partition(':')
            if k.strip():
                st[k.strip().lower()] = v.strip().lower()
        return st

    def _open_styled(self, st, color=None):
        opened = []
        c = color or st.get('color')
        if c and self.COLOR.match(c):
            self.out.append('<span style="color:%s">' % c.strip())
            opened.append('span')
        if st.get('font-weight') in ('bold', 'bolder', '600', '700', '800', '900'):
            self.out.append('<b>')
            opened.append('b')
        if st.get('font-style') == 'italic':
            self.out.append('<i>')
            opened.append('i')
        if 'underline' in (st.get('text-decoration') or '') + (st.get('text-decoration-line') or ''):
            self.out.append('<u>')
            opened.append('u')
        return opened

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'br':
            self.out.append('<br>')
            return
        if tag in ('b', 'strong'):
            self.out.append('<b>')
            self.stack.append((tag, ['b']))
        elif tag in ('i', 'em'):
            self.out.append('<i>')
            self.stack.append((tag, ['i']))
        elif tag == 'u':
            self.out.append('<u>')
            self.stack.append((tag, ['u']))
        elif tag == 'a':
            href = str(dict(attrs).get('href') or '').strip()
            if re.match(r'(https?://|mailto:)[^\s"<>]+\Z', href, re.I):
                self.out.append('<a href="%s" style="color:#1d4ed8">' % html.escape(href, quote=True))
                self.stack.append((tag, ['a']))
            else:
                self.stack.append((tag, []))
        elif tag in ('span', 'font'):
            st = self._style(attrs)
            self.stack.append((tag, self._open_styled(
                st, dict(attrs).get('color') if tag == 'font' else None)))
        elif tag in ('div', 'p'):
            # A new paragraph typed in the editor is a line break here.
            if self.out and not self.out[-1].endswith('<br>'):
                self.out.append('<br>')
            self.stack.append((tag, []))
        else:
            self.stack.append((tag, []))

    def handle_endtag(self, tag):
        tag = tag.lower()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                while len(self.stack) > i:
                    _t, opened = self.stack.pop()
                    for o in reversed(opened):
                        self.out.append('</%s>' % o)
                return

    def handle_startendtag(self, tag, attrs):
        if tag.lower() == 'br':
            self.out.append('<br>')

    def handle_data(self, data):
        if any(t in ('script', 'style', 'title', 'head') for t, _o in self.stack):
            return
        self.out.append(html.escape(data, quote=False))

    def result(self):
        while self.stack:
            _t, opened = self.stack.pop()
            for o in reversed(opened):
                self.out.append('</%s>' % o)
        text = ''.join(self.out)
        text = re.sub(r'(<br>)+\Z', '', text)
        return re.sub(r'\A(<br>)+', '', text).strip()


def text_rich_clean(value):
    p = _RichClean()
    p.feed(str(value or ''))
    p.close()
    return p.result()


def text_samples(lang='cs'):
    site = str(CONFIG.get('site_name') or socket.gethostname())
    out = dict(TEXT_SAMPLES)
    out.update({'code': '482913', 'minutes': max(1, int(CONFIG.get('code_ttl_s') or 300) // 60),
                'site': site, 'name': 'Jan Novák' if lang == 'cs' else 'Jan Novak',
                'account': 'jan.novak@example.cz', 'dest': 'j•••@example.cz', 'by': 'admin'})
    return out


def text_check(field, value):
    """A field's new text, cleaned, or ValueError saying what is wrong."""
    key, kind, label, allowed, _where = field
    if value is not None and not isinstance(value, str):
        raise ValueError('%s: a piece of text' % label)
    value = str(value if value is not None else '')
    value = value.replace('\r\n', '\n').replace('\r', '\n')
    if kind != 'text':
        value = value.replace('\n', ' ')
    value = ''.join(c for c in value if c in '\n\t' or ord(c) >= 32)
    if kind == 'rich':
        value = text_rich_clean(value)
    else:
        value = value.strip() if kind == 'line' else value.strip('\n ')
    if len(value) > TEXT_MOST[kind]:
        raise ValueError('%s: at most %d characters' % (label, TEXT_MOST[kind]))
    try:
        parts = list(string.Formatter().parse(value))
    except ValueError:
        raise ValueError('%s: a { or } on its own - write it twice, {{ or }}' % label)
    for _lit, name, spec, conv in parts:
        if name is None:
            continue
        if name in allowed and (spec or conv):
            raise ValueError('%s: write {%s} with nothing after its name' % (label, name))
        if name not in allowed:
            raise ValueError('%s: {%s} is not something this text can have - it can have %s'
                             % (label, name, ', '.join('{%s}' % a for a in allowed) or 'none'))
    try:
        value.format(**text_samples())
    except (ValueError, IndexError, KeyError) as e:
        raise ValueError('%s: a { or } on its own - write it twice, {{ or }} (%s)' % (label, e))
    if field[4] in ('subject', 'sms') and not value.strip():
        raise ValueError('%s cannot be empty' % label)
    return value


# ---- what the editor shows -------------------------------------------------------
TEXT_MARK = '⟦f:%s⟧'


def text_words(mid, lang, fields=None, mark=False):
    """The words of a message's group with those of the editor (`fields`,
    not yet saved) over the saved ones; `mark`: each field of this message
    as a mark the editor puts its box in."""
    m = text_message(mid)
    w = texts_for(m['group'], lang)
    for k, v in (fields or {}).items():
        if any(f[0] == k for f in m['fields']):
            w[k] = v
    if mark:
        for f in m['fields']:
            w[f[0]] = TEXT_MARK % f[0]
    return w


def text_render(store, mid, lang, fields=None, mark=False):
    """A message as it would go out, with sample values: the mail's HTML,
    its subject and its text; the SMS; a text's lines."""
    m = text_message(mid)
    w = text_words(mid, lang, fields, mark)
    smp = text_samples(lang)
    out = {'id': mid, 'lang': lang}
    if m['kind'] == 'mail' and m['group'] == 'code':
        out['html'] = code_mail_html(smp['code'], m['purpose'], lang, smp['account'], smp['name'],
                                     w=w)
        sub = w[code_purpose(m['purpose'])['subject']]
        body = w[code_purpose(m['purpose'])['body']]
        out['subject'] = sub.format(**smp)
        out['text'] = body.format(**smp)
    elif m['kind'] == 'mail' and callable(m.get('render')):
        out.update(m['render'](w, smp, lang) or {})
    elif m['kind'] == 'sms':
        text = w[m['fields'][0][0]].format(**smp)
        out['sms'] = sms_plain(text)
        out['sms_written'] = text
    else:
        out['lines'] = {f[0]: w[f[0]].format(**smp) for f in m['fields']}
    return out


def text_state(store, mid=None):
    """Every message, its fields, their defaults and what is saved now."""
    out = []
    for m in TEXT_MESSAGES:
        if mid and m['id'] != mid:
            continue
        one = {'id': m['id'], 'kind': m['kind'], 'title': m['title'], 'says': m['says'],
               'short': m.get('short') or m['title'],
               'fields': [], 'saved': {}}
        for lang in TEXT_LANGS:
            sv = text_saved(store, m['id'], lang)
            one['saved'][lang] = {'at': sv.get('at'), 'by': sv.get('by'),
                                  'changed': sorted(k for k in sv['f']
                                                    if any(f[0] == k for f in m['fields']))}
        for key, kind, label, allowed, where in m['fields']:
            f = {'key': key, 'kind': kind, 'label': label, 'where': where,
                 'placeholders': list(allowed), 'default': {}, 'value': {}}
            for lang in TEXT_LANGS:
                d = text_defaults(m['group'], lang).get(key, '')
                f['default'][lang] = d
                f['value'][lang] = text_saved(store, m['id'], lang)['f'].get(key, d)
            one['fields'].append(f)
        out.append(one)
    return out


def text_save(store, mid, lang, fields, by, was_at=None):
    """The fields of a message in one language saved; those equal to their
    default are not kept (so a default changed in a later version reaches
    them). Refused if somebody else saved it meanwhile (`was_at`)."""
    m = text_message(mid)
    if not m or lang not in TEXT_LANGS:
        raise ValueError('no such message or language')
    k = 'texts:%s:%s' % (mid, lang)
    raw = store.get_meta(k)
    now = text_saved(store, mid, lang)
    if was_at is not None and (now.get('at') or 0) != (was_at or 0):
        raise TextConflict('%s changed these words meanwhile (%s) - load them again'
                           % (now.get('by') or 'somebody', stamp(now.get('at'))))
    defaults = text_defaults(m['group'], lang)
    keep = dict(now['f'])
    for f in m['fields']:
        if f[0] not in fields:
            continue
        v = text_check(f, fields[f[0]])
        if v == defaults.get(f[0]):
            keep.pop(f[0], None)
        else:
            keep[f[0]] = v
    new = {'f': keep, 'at': time.time(), 'by': by}
    if raw is None:
        store.set_meta(k, json.dumps(new))
    elif not store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?', (json.dumps(new), k, raw)):
        raise TextConflict('somebody saved these words at the same moment - load them again')
    texts_forget()
    return new


def text_reset(store, mid, lang, keys=None):
    """A message in one language - or only `keys` of it - back to its default."""
    m = text_message(mid)
    if not m or lang not in TEXT_LANGS:
        raise ValueError('no such message or language')
    k = 'texts:%s:%s' % (mid, lang)
    if not keys:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
    else:
        for _round in range(8):
            raw = store.get_meta(k)
            if raw is None:
                break
            now = text_saved(store, mid, lang)
            for key in keys:
                now['f'].pop(key, None)
            if store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                            (json.dumps(dict(now, at=time.time())), k, raw)):
                break
    texts_forget()


class TextConflict(ValueError):
    pass


import ftplib
import tarfile


