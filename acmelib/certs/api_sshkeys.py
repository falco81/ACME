# -*- coding: utf-8 -*-
"""
The SSH keys of the modules - a field of the type `sshkey` - made and kept as
isemon makes and keeps the key it reaches a firewall with (isemon 1.10.276,
"Make a key · Use my own · Download it · Forget it · Try reaching it").

The private half is made here (ssh-keygen in a folder of its own in /dev/shm,
taken away after) or brought, and kept sealed in the module's settings, as
every secret is: config[<field>] is the sealed private key. Beside it, not
secret, config[<field>.sshkey] = {public, fp, type, bits, made, by, how}
(how: made | own | pasted - a key pasted before there was this card), and,
for a key brought with a passphrase, the field's `pass_key` (key_pass) holds
that passphrase, sealed - the runtime hands it to ssh as it always did.

The page is never sent the private half: what it shows is the public half
and the fingerprint. "Download it" hands over the private half to a full
administrator and writes that it did, and by whom, into Events.

A form not saved yet (a new target) has no row to keep a key in: what is
made or brought there is a draft, kept here sealed for a day under a token
(meta sshkey:draft:<token>), and the form's field holds "sshkey:draft:<token>"
- saved, the draft becomes the target's key (family_save below); tried, it is
the key tried (family_test, and Try reaching it).

Routes (POST unless said; {family: target|challenge, id | (kind + draft),
field}):

    GET  /api/sshkey/info        can ssh-keygen be run, this node's name, the
                                 addresses acme reaches others from (from=)
    POST /api/sshkey/show        what is kept: public half, fingerprint, ...
    POST /api/sshkey/make        a new pair (key_type: ed25519 | rsa4096)
    POST /api/sshkey/use_own     {pem, passphrase}: a key of your own
    POST /api/sshkey/forget      the key deleted
    POST /api/sshkey/download    {half: public | private} as a file
    POST /api/sshkey/try         a real sign-in that changes nothing, step by
                                 step ({config}: the form as it is, saved or not)
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import secrets as _rand
import shutil
import subprocess
import sys
import tempfile
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import deployer, jobs, runtime
from acmelib.plugins.base import PluginError

KEY_TYPES = {'ed25519': ['-t', 'ed25519'], 'rsa4096': ['-t', 'rsa', '-b', '4096']}
META = '.sshkey'
DRAFT = 'sshkey:draft:'
DRAFT_TTL = 86400
FAMILY_WORDS = {'target': 'target', 'challenge': 'validation', 'issuer': 'source'}
FAMILY_NAMES = {'target': 'target', 'targets': 'target', 'challenge': 'challenge',
                'challenges': 'challenge', 'validation': 'challenge', 'validations': 'challenge',
                'issuer': 'issuer', 'issuers': 'issuer', 'source': 'issuer', 'sources': 'issuer'}
# What "Try reaching it" runs once signed in, where the field says nothing: it
# reads, and changes nothing.
TRY_COMMAND = 'id -un; uname -n'


# ---------------------------------------------------------------------------
# The fields
# ---------------------------------------------------------------------------
def sshkey_fields(cls):
    return [f for f in (getattr(cls, 'fields', None) or []) if f.get('type') == 'sshkey']


def meta_key(f):
    return f['key'] + META


def pass_key(f):
    return str(f.get('pass_key') or '')


# ---------------------------------------------------------------------------
# ssh-keygen
# ---------------------------------------------------------------------------
def can_keygen():
    return bool(shutil.which('ssh-keygen'))


def _need_keygen():
    if not can_keygen():
        raise ValueError('ssh-keygen is not on this machine, so a key cannot be made or read '
                         'here: dnf install openssh-clients. A password still works.')


@contextlib.contextmanager
def workdir():
    """A folder only this process may read, in memory where there is /dev/shm,
    taken away with whatever is in it."""
    base = '/dev/shm' if os.path.isdir('/dev/shm') and os.access('/dev/shm', os.W_OK) else None
    d = tempfile.mkdtemp(prefix='acme-sshkey-', dir=base)
    try:
        os.chmod(d, 0o700)
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def _keygen(argv, d, passphrase=''):
    """ssh-keygen run, a passphrase given through SSH_ASKPASS - never on the
    command line, where `ps` shows it."""
    env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force')
    if passphrase:
        ask = os.path.join(d, 'ask')
        with open(ask, 'w') as f:
            f.write('#!/bin/sh\nprintf "%s\\n" "$ACME_SSHKEY_SECRET"\n')
        os.chmod(ask, 0o700)
        env.update(SSH_ASKPASS=ask, ACME_SSHKEY_SECRET=passphrase)
    else:
        env.pop('SSH_ASKPASS', None)
    return subprocess.run(['ssh-keygen'] + argv, capture_output=True, text=True, timeout=120,
                          env=env, stdin=subprocess.DEVNULL)


def facts(public):
    """{bits, fp, type, comment} of a public key line, as ssh-keygen reads it."""
    got = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'],
                         input=str(public).strip() + '\n', capture_output=True, text=True,
                         timeout=20)
    bits = got.stdout.split()
    if got.returncode != 0 or len(bits) < 2:
        raise ValueError('ssh-keygen does not read that key')
    kind = bits[-1].strip('()') if bits[-1].startswith('(') else ''
    parts = str(public).split()
    return {'bits': int(bits[0]) if bits[0].isdigit() else 0, 'fp': bits[1], 'type': kind,
            'comment': ' '.join(parts[2:])[:120] if len(parts) > 2 else ''}


def make_pair(key_type, comment):
    """A new pair: (private, public)."""
    if key_type not in KEY_TYPES:
        raise ValueError('a key is ed25519, or rsa4096 for something old that needs RSA')
    _need_keygen()
    comment = re.sub(r'[^A-Za-z0-9@._ -]', '', str(comment or ''))[:80].strip() or 'acme'
    with workdir() as d:
        path = os.path.join(d, 'k')
        got = _keygen(['-q'] + KEY_TYPES[key_type] + ['-N', '', '-C', comment, '-f', path], d)
        if got.returncode != 0:
            raise ValueError('no key could be made: ssh-keygen: %s'
                             % (got.stderr or got.stdout).strip()[:200])
        with open(path) as f:
            private = f.read()
        with open(path + '.pub') as f:
            public = f.read().strip()
    return private, public


def read_own(text, passphrase='', strip=False):
    """A private key brought: (private, public, passphrase still needed). It is
    checked here - a public half, a locked key without its passphrase, a wrong
    passphrase are each refused in words. `strip`: the passphrase taken off
    (for a field with nowhere to keep one)."""
    _need_keygen()
    text = str(text or '').replace('\r\n', '\n').replace('\r', '\n').strip()
    passphrase = str(passphrase or '')
    if not text:
        raise ValueError('nothing was given: paste the private key, or read it from a file')
    if re.match(r'^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)', text):
        raise ValueError('that is the public half - the private one is needed (the file '
                         'without .pub)')
    if 'PuTTY-User-Key-File' in text:
        raise ValueError('that is a PuTTY key: save it from PuTTYgen as an OpenSSH key '
                         '(Conversions → Export OpenSSH key) and bring that')
    if 'PRIVATE KEY-----' not in text:
        raise ValueError('that is not a private key: it starts -----BEGIN OPENSSH PRIVATE '
                         'KEY----- (or another PEM private key)')
    private = text + '\n'
    with workdir() as d:
        path = os.path.join(d, 'k')
        _write(path, private)
        got = _keygen(['-y', '-P', '', '-f', path], d)
        need = ''
        if got.returncode != 0:
            said = (got.stderr or got.stdout).strip()
            low = said.lower()
            locked = 'passphrase' in low or 'incorrect' in low or 'ENCRYPTED' in text
            if not locked:
                raise ValueError('ssh-keygen does not read it: %s' % said[:200])
            if not passphrase:
                raise ValueError('the key is locked with a passphrase: give it too')
            got = _keygen(['-y', '-f', path], d, passphrase)
            if got.returncode != 0:
                raise ValueError('that passphrase does not open the key')
            need = passphrase
        public = got.stdout.strip().splitlines()[0] if got.stdout.strip() else ''
        if not public:
            raise ValueError('ssh-keygen does not read it')
        if need and strip:
            off = _keygen(['-p', '-N', '', '-f', path], d, need)
            if off.returncode != 0:
                raise ValueError('its passphrase could not be taken off: %s'
                                 % (off.stderr or off.stdout).strip()[:200])
            with open(path) as f:
                private = f.read()
            need = ''
    return private, public, need


def public_of(private, passphrase=''):
    """The public half of a key kept (a key pasted before this card), or ''."""
    if not private or not can_keygen():
        return ''
    try:
        return read_own(private, passphrase)[1]
    except ValueError:
        return ''


def meta_for(public, how, by):
    m = {'public': public, 'how': how, 'made': time.time(), 'by': str(by or '')[:190]}
    try:
        m.update(facts(public))
    except (ValueError, OSError, subprocess.SubprocessError):
        pass
    return m


def view(cfg, f):
    """What the page is told of one key - never its private half."""
    m = cfg.get(meta_key(f)) if isinstance(cfg.get(meta_key(f)), dict) else {}
    has = bool(cfg.get(f['key']))
    out = {'has': has, 'field': f['key']}
    if has:
        for k in ('public', 'fp', 'type', 'bits', 'comment', 'made', 'by', 'how'):
            if m.get(k) not in (None, ''):
                out[k] = m[k]
        out.setdefault('how', 'pasted')
        out['locked'] = bool(pass_key(f) and cfg.get(pass_key(f)))
    return out


# ---------------------------------------------------------------------------
# Drafts: a key made in a form not saved yet
# ---------------------------------------------------------------------------
def _draft_k(token):
    return DRAFT + token


def _drafts_pruned(store):
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (DRAFT + '%',)):
        try:
            at = float((json.loads(r['v']) or {}).get('at') or 0)
        except (TypeError, ValueError):
            at = 0
        if at < time.time() - DRAFT_TTL:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))


def draft_new(store, family, kind, f, private, passphrase, meta, by):
    _drafts_pruned(store)
    token = _rand.token_hex(16)
    bind = _draft_k(token)
    store.set_meta(bind, json.dumps({
        'family': family, 'kind': kind, 'field': f['key'], 'at': time.time(),
        'by': str(by or '')[:190], 'meta': meta,
        'key': E.seal_secret(private, bind),
        'pass': E.seal_secret(passphrase, bind + ':pass') if passphrase else ''}))
    return token


def draft_token(v):
    v = str(v or '')
    if v.startswith(DRAFT):
        v = v[len(DRAFT):]
    return v if re.match(r'^[0-9a-f]{32}\Z', v) else ''


def draft_get(store, token, family=None, kind=None, field=None):
    token = draft_token(token)
    raw = store.get_meta(_draft_k(token)) if token else None
    if not raw:
        raise ValueError('the key made in this form is no longer here (a day old, or the form '
                         'was saved already): make it again')
    d = json.loads(raw)
    if (family and d.get('family') != family) or (kind and d.get('kind') != kind) or \
            (field and d.get('field') != field):
        raise ValueError('that key was made for another form: make it again')
    if float(d.get('at') or 0) < time.time() - DRAFT_TTL:
        draft_drop(store, token)
        raise ValueError('the key made in this form is more than a day old: make it again')
    bind = _draft_k(token)
    d['private'] = E.unseal_secret(d.get('key'), bind) or ''
    d['passphrase'] = E.unseal_secret(d.get('pass'), bind + ':pass') if d.get('pass') else ''
    if not d['private']:
        raise ValueError('the key made in this form cannot be opened here: make it again')
    return d


def draft_drop(store, token):
    token = draft_token(token)
    if token:
        store.db.run('DELETE FROM meta WHERE k = ?', (_draft_k(token),))


# ---------------------------------------------------------------------------
# Kept in a saved row
# ---------------------------------------------------------------------------
def _place(family, row):
    return '%s:%s' % (S.TABLE_OF[family], row['id'])


def _cfg(row):
    got = S.jload(row.get('config'), {}) or {}
    return got if isinstance(got, dict) else {}


def _event(store, family, row, words, by, level='info'):
    store.add_event('certificates', '%s %s: %s by %s' % (
        FAMILY_WORDS.get(family, family), row['name'], words, by), level, who=by)


def put_key(store, family, row, f, private, passphrase, meta):
    """The key kept in the row (None: forgotten)."""
    cfg = _cfg(row)
    place = _place(family, row)
    pk = pass_key(f)
    if private is None:
        for k in (f['key'], meta_key(f), pk):
            if k:
                cfg.pop(k, None)
    else:
        cfg[f['key']] = E.seal_secret(private, '%s:%s' % (place, f['key']))
        cfg[meta_key(f)] = meta
        if pk:
            if passphrase:
                cfg[pk] = E.seal_secret(passphrase, '%s:%s' % (place, pk))
            else:
                cfg.pop(pk, None)
    store.db.update(S.TABLE_OF[family], row['id'], {'config': json.dumps(cfg),
                                                     'updated': time.time()})
    row['config'] = json.dumps(cfg)
    return cfg


def opened(family, row, f):
    """(private, passphrase) of the key kept in the row."""
    cfg = S.plugin_config(family, row)
    return cfg.get(f['key']) or '', (cfg.get(pass_key(f)) or '') if pass_key(f) else ''


def legacy_meta(store, family, row, f):
    """A key pasted before there was this card: its public half worked out once
    and kept beside it, so it shows as "your own key"."""
    cfg = _cfg(row)
    m = cfg.get(meta_key(f))
    if not cfg.get(f['key']) or (isinstance(m, dict) and m.get('public')):
        return cfg
    private, pp = opened(family, row, f)
    public = public_of(private, pp)
    if not public:
        return cfg
    m = meta_for(public, 'pasted', '')
    m['made'] = None
    cfg[meta_key(f)] = m
    store.db.update(S.TABLE_OF[family], row['id'], {'config': json.dumps(cfg)})
    row['config'] = json.dumps(cfg)
    return cfg


# ---------------------------------------------------------------------------
# What a call is about
# ---------------------------------------------------------------------------
class Ref(object):
    def __init__(self, store, b):
        self.family = FAMILY_NAMES.get(str(b.get('family') or 'target').strip().lower())
        if not self.family:
            raise ValueError('family is target or challenge')
        ident = b.get('id')
        self.row = S.plugin_row(store, self.family, A._id(ident)) \
            if ident not in (None, '', 0) else None
        if ident not in (None, '', 0) and not self.row:
            raise LookupError('there is no such %s' % FAMILY_WORDS[self.family])
        self.kind = str(b.get('kind') or (self.row or {}).get('kind') or '')
        self.cls = S.plugin_class(self.family, self.kind)
        if self.cls is None:
            raise ValueError('there is no %s module "%s"' % (FAMILY_WORDS[self.family], self.kind))
        if self.row and self.row.get('kind') != self.kind:
            self.row = None             # another module chosen in the form, not saved: a draft
        fields = sshkey_fields(self.cls)
        want = str(b.get('field') or '')
        self.f = next((f for f in fields if f['key'] == want), None) if want else \
            (fields[0] if fields else None)
        if self.f is None:
            raise ValueError('%s has no SSH key%s' % (self.kind, ' called %s' % want if want
                                                      else ''))
        self.draft = draft_token(b.get('draft'))
        self.name = str((self.row or {}).get('name') or b.get('name') or self.kind)[:120]

    def words(self):
        return '%s %s' % (FAMILY_WORDS[self.family], self.name)


def file_slug(name):
    return re.sub(r'[^A-Za-z0-9._-]+', '-', str(name or '')).strip('-.')[:60] or 'key'


def key_view(store, ref, by=None):
    """The key of a saved row, or of the draft named."""
    if ref.row:
        return view(legacy_meta(store, ref.family, ref.row, ref.f), ref.f)
    if ref.draft:
        try:
            d = draft_get(store, ref.draft, ref.family, ref.kind, ref.f['key'])
        except ValueError:
            return {'has': False, 'field': ref.f['key'], 'gone': True}
        out = view({ref.f['key']: 'x', meta_key(ref.f): d.get('meta') or {}}, ref.f)
        out.update({'draft': DRAFT + ref.draft, 'locked': bool(d.get('passphrase'))})
        return out
    return {'has': False, 'field': ref.f['key']}


def keep(store, ref, private, passphrase, meta, by, words):
    if ref.row:
        put_key(store, ref.family, ref.row, ref.f, private, passphrase, meta)
        _event(store, ref.family, ref.row, words, by)
        return key_view(store, ref)
    if ref.draft:
        draft_drop(store, ref.draft)
    ref.draft = draft_new(store, ref.family, ref.kind, ref.f, private, passphrase, meta, by)
    return key_view(store, ref)


def do_make(store, b, by):
    ref = Ref(store, b)
    key_type = str(b.get('key_type') or ref.f.get('key_type') or 'ed25519')
    private, public = make_pair(key_type, 'acme@%s' % E.node_name())
    return keep(store, ref, private, '', meta_for(public, 'made', by), by,
                'a new SSH key was made (%s)' % key_type)


def do_use_own(store, b, by):
    ref = Ref(store, b)
    text = A._text(b, 'pem', 64000)
    if not text.strip() and b.get('pem_b64'):
        text = A._b64(b.get('pem_b64'), 'pem_b64').decode('utf-8', 'replace')
    private, public, need = read_own(text, A._text(b, 'passphrase', 1000),
                                     strip=not pass_key(ref.f))
    return keep(store, ref, private, need, meta_for(public, 'own', by), by,
                'an SSH key of their own was given%s' % (' (with its passphrase)' if need else ''))


def do_forget(store, b, by):
    ref = Ref(store, b)
    if ref.row:
        put_key(store, ref.family, ref.row, ref.f, None, '', None)
        _event(store, ref.family, ref.row, 'the SSH key was forgotten', by, 'warn')
    elif ref.draft:
        draft_drop(store, ref.draft)
        ref.draft = ''
    return {'has': False, 'field': ref.f['key'], 'message': 'the key is gone'}


def do_download(store, b, s):
    ref = Ref(store, b)
    half = str(b.get('half') or 'public')
    by = A.who(s)
    if ref.row:
        private, pp = opened(ref.family, ref.row, ref.f)
        v = key_view(store, ref)
    elif ref.draft:
        d = draft_get(store, ref.draft, ref.family, ref.kind, ref.f['key'])
        private, pp = d['private'], d['passphrase']
        v = key_view(store, ref)
    else:
        private, pp, v = '', '', {}
    if not private:
        raise LookupError('there is no key')
    slug = 'acme-%s' % file_slug(ref.name)
    if half == 'public':
        public = v.get('public') or public_of(private, pp)
        if not public:
            raise ValueError('its public half cannot be worked out here')
        return {'text': public + '\n', 'file': slug + '.pub', 'type': 'text/plain'}
    if half != 'private':
        raise ValueError('half is public or private')
    if not A.may(s, 'fulladmin'):
        raise E.ApiError(403, A.ROLE_WORDS['fulladmin'])
    if ref.row:
        _event(store, ref.family, ref.row, 'the private SSH key was downloaded', by, 'warn')
    else:
        store.add_event('certificates', '%s downloaded the private SSH key made in the form of '
                        'a new %s (%s)' % (by, FAMILY_WORDS[ref.family], ref.name), 'warn', who=by)
    return {'text': private if private.endswith('\n') else private + '\n', 'file': slug,
            'type': 'application/octet-stream', 'locked': bool(pp)}


# ---------------------------------------------------------------------------
# Drafts attached on save, and tried by Test
# ---------------------------------------------------------------------------
def _with_drafts(store, family, kind, config, by, plain_pass=True, pasted=False):
    """The form's config with each draft token replaced by its key (and its
    passphrase): (config, {field: (meta, passphrase, token)})."""
    cls = S.plugin_class(family, kind)
    fields = sshkey_fields(cls)
    if not fields or not isinstance(config, dict):
        return config, {}
    given, took = dict(config), {}
    for f in fields:
        v = given.get(f['key'])
        if isinstance(v, str) and v.startswith(DRAFT):
            d = draft_get(store, v, family, kind, f['key'])
            given[f['key']] = d['private']
            if pass_key(f) and plain_pass:
                given[pass_key(f)] = d['passphrase'] or ''
            took[f['key']] = (d.get('meta') or {}, d['passphrase'], draft_token(v))
        elif pasted and isinstance(v, str) and 'PRIVATE KEY-----' in v:
            # Pasted whole (the API as before, acme --target-edit --set key=@file:...):
            # kept as it was given, as it always was; its public half when it reads.
            pp = (given.get(pass_key(f)) or '') if pass_key(f) else ''
            try:
                private, public, need = read_own(v, pp, strip=not pass_key(f))
                given[f['key']] = private
                meta = meta_for(public, 'own', by)
            except ValueError:
                need, meta = pp, {'how': 'pasted', 'made': time.time(), 'by': str(by or '')[:190]}
            took[f['key']] = (meta, need, '')
    return given, took


_ORIG = {}


def family_save(store, family, b, by):
    """api.family_save, with the SSH keys of the form: a draft made in it becomes
    the row's key; what is kept beside a key that stays (its public half, its
    passphrase) stays with it."""
    orig = _ORIG['save']
    row = S.plugin_row(store, family, A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.plugin_class(family, kind)
    fields = sshkey_fields(cls)
    if not fields or not isinstance(b.get('config'), dict):
        return orig(store, family, b, by)
    old = _cfg(row) if row and row.get('kind') == kind else {}
    given, took = _with_drafts(store, family, kind, b['config'], by, plain_pass=False,
                               pasted=True)
    ident = orig(store, family, dict(b, config=given), by)
    now = S.plugin_row(store, family, ident)
    cfg = _cfg(now)
    place = _place(family, now)
    for f in fields:
        pk = pass_key(f)
        if f['key'] in took:
            meta, pp, token = took[f['key']]
            cfg[meta_key(f)] = meta
            if pk:
                if pp:
                    cfg[pk] = E.seal_secret(pp, '%s:%s' % (place, pk))
                else:
                    cfg.pop(pk, None)
            if token:
                draft_drop(store, token)
            _event(store, family, now, 'the SSH key %s was put in place'
                   % ('made in the form' if meta.get('how') == 'made' else 'given in the form'), by)
        elif cfg.get(f['key']):
            for k in (meta_key(f), pk):
                if k and k not in cfg and old.get(k):
                    cfg[k] = old[k]
        else:
            for k in (meta_key(f), pk):
                if k:
                    cfg.pop(k, None)
    if cfg != _cfg(now):
        store.db.update(S.TABLE_OF[family], ident, {'config': json.dumps(cfg)})
    return ident


def family_test(store, family, b, by, echo=None):
    """api.family_test, a draft key of the form tried as the key."""
    row = S.plugin_row(store, family, A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    if isinstance(b.get('config'), dict):
        given, _took = _with_drafts(store, family, kind, b['config'], by)
        b = dict(b, config=given)
    return _ORIG['test'](store, family, b, by, echo=echo)


def install():
    """family_save and family_test of api.py, with the drafts - the routes there
    call them by name, so these are the ones called."""
    if 'save' not in _ORIG:
        _ORIG['save'] = A.family_save
        _ORIG['test'] = A.family_test
        A.family_save = family_save
        A.family_test = family_test


# ---------------------------------------------------------------------------
# Try reaching it: a real sign-in, nothing changed
# ---------------------------------------------------------------------------
def _hostport(text, port=22):
    s = str(text or '').strip()
    m = re.match(r'^\[([^\]]+)\](?::(\d+))?\Z', s)
    if m:
        return m.group(1), int(m.group(2) or port)
    if s.count(':') == 1:
        h, p = s.split(':')
        return h, int(p) if p.isdigit() else port
    return s, port


def sessions(obj, family, f):
    """[(where, open())] - the SSH sign-ins of the module, each a session."""
    if hasattr(obj, 'sshkey_sessions'):
        return obj.sshkey_sessions(f['key'])
    if family == 'challenge':
        from acmelib.plugins.challenges._common import ssh_conn as ch_conn
        if hasattr(obj, 'hosts'):
            hosts = obj.hosts()
        else:
            hosts = [_hostport(obj.c('host', ''))]
        out = []
        for host, port in hosts:
            if not host:
                continue
            out.append(('%s:%s' % (host, port),
                        (lambda h=host, p=port: obj.ctx.ssh(ch_conn(obj, h, p)))))
        if not out:
            raise PluginError('there is no machine to reach yet: fill its address in',
                              retry=False)
        return out
    prefix = str(f.get('ssh_prefix') or '')
    host = obj.c('host')
    if not host:
        raise PluginError('there is no address to reach yet: fill it in', retry=False)
    if prefix or not hasattr(obj, 'ssh'):
        from acmelib.plugins.targets._common import ssh_conn as tg_conn
        conn = tg_conn(obj, prefix)
        return [('%s:%s' % (host, conn['port']), lambda: obj.ctx.ssh(conn))]
    port = obj.c('ssh_port') if any(x.get('key') == 'ssh_port' for x in obj.fields) \
        else obj.c('port')
    return [('%s:%s' % (host, port or 22), obj.ssh)]


# ---- the host keys it sees, for the form's "Host keys" ---------------------
# Try reaching it reads the host key(s) each machine shows (ssh-keyscan, as a
# first connection does) and says them back with what the form pins for that
# machine: `new` (nothing pinned - the page adds the line), `same` (one pinned
# is one shown) or `other` (what is pinned is not what it shows: somebody in
# between, or the machine reinstalled - the page warns, and replaces it only
# when the person says so). Nothing is written here: the form's Save keeps it.
HOSTKEY_RANK = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa')


def hostkey_key(cls, f):
    """The form's field the host keys are pinned in, for the key field `f`."""
    keys = [x.get('key') for x in (getattr(cls, 'fields', None) or [])]
    for k in (f.get('hostkey_key'), str(f.get('ssh_prefix') or '') + 'hostkey', 'hostkey'):
        if k and k in keys:
            return k
    return None


def _where(where, port=22):
    s = str(where or '')
    if ':' in s and s.rsplit(':', 1)[1].isdigit():
        h, p = s.rsplit(':', 1)
        return h.strip('[]'), int(p)
    return s.strip('[]'), port


def hostkey_line(host, port, typ, key):
    """A known_hosts line: 'host type key', '[host]:port type key' off port 22."""
    h = str(host).strip('[]')
    return '%s %s %s' % (h if int(port or 22) == 22 else '[%s]:%d' % (h, int(port)), typ, key)


def _key_of(line):
    """(type, base64) of a known_hosts line, or None."""
    got = runtime.hostkey_lines(line)
    if not got:
        return None
    parts = got[0].split()
    return parts[1], parts[2]


def _rank(typ):
    return HOSTKEY_RANK.index(typ) if typ in HOSTKEY_RANK else len(HOSTKEY_RANK)


def _field_lines(v):
    if v in (None, ''):
        return []
    if isinstance(v, (list, tuple)):
        v = '\n'.join(str(x) for x in v)
    return [x.strip() for x in str(v).splitlines() if x.strip() and not x.strip().startswith('#')]


def _line_hosts(line):
    """The hosts a known_hosts line is for ('' when it names none)."""
    parts = line.split()
    if parts and parts[0].startswith('@'):
        parts = parts[1:]
    if not parts or re.match(r'^(ssh-|ecdsa-|sk-)', parts[0]):
        return set()
    out = set()
    for x in parts[0].split(','):
        m = re.match(r'^\[([^\]]+)\](?::\d+)?\Z', x)
        out.add((m.group(1) if m else x).lower())
    return out


def hostkey_pinned(lines, host, per_host=True):
    """The lines of the field that pin `host`: those naming it (a form for
    several machines, as challenges/_common.hostkey_for), or every line (a
    form for one machine, as runtime.SshSession reads them)."""
    if not per_host:
        return list(lines)
    h = str(host).strip('[]').lower()
    return [x for x in lines if h in _line_hosts(x)]


def hostkey_report(seen, value, per_host=True):
    """What the page is told of the host keys seen: [{where, host, port, line,
    type, fp, keys, status: new|same|other, pinned, pinned_fps}] - `seen` is
    [(host, port, known_hosts text)], `value` the form's field as it is."""
    lines = _field_lines(value)
    out = []
    for host, port, text in seen:
        keys = []
        for x in runtime.hostkey_lines(text):
            typ, key = x.split()[1:3]
            if (typ, key) not in [k[:2] for k in keys]:
                keys.append((typ, key, hostkey_line(host, port, typ, key)))
        if not keys:
            continue
        keys.sort(key=lambda k: _rank(k[0]))
        best = keys[0]
        pinned = hostkey_pinned(lines, host, per_host)
        have = set(filter(None, (_key_of(x) for x in pinned)))
        status = 'same' if any(k[:2] in have for k in keys) else ('other' if pinned else 'new')
        out.append({'where': '%s:%s' % (host, port), 'host': host, 'port': port,
                    'line': best[2], 'type': best[0],
                    'fp': runtime.hostkey_fingerprint(best[2]),
                    'keys': [runtime.hostkey_fingerprint(k[2]) for k in keys],
                    'status': status, 'pinned': pinned,
                    'pinned_fps': [runtime.hostkey_fingerprint(x) for x in pinned
                                   if _key_of(x)]})
    return out


def _overlay(cfg, given, cls):
    secrets_ = S.secret_fields(cls)
    for k, v in (given or {}).items():
        if k in secrets_ and (v in (None, '') or E.is_masked(v)):
            continue                    # "" or the dots shown: the one kept
        cfg[k] = v
    return cfg


def do_try(store, b, by, keep_hostkey=False):
    """A real sign-in that changes nothing. The host keys each machine shows
    come back as `hostkeys` (hostkey_report) for the form to pin; a host key
    taken as the first seen is kept in the saved target only with
    `keep_hostkey` (the command line, which has no form to keep it)."""
    ref = Ref(store, b)
    cfg = S.plugin_config(ref.family, ref.row) if ref.row else {}
    cfg = _overlay(cfg, A._dict(b.get('config'), 'config'), ref.cls)
    if ref.draft and not cfg.get(ref.f['key']):
        cfg[ref.f['key']] = DRAFT + ref.draft
    cfg, _took = _with_drafts(store, ref.family, ref.kind, cfg, by)
    command = str(ref.f.get('try_command') or TRY_COMMAND)
    fp = ''
    if cfg.get(ref.f['key']):
        v = key_view(store, ref) if (ref.row or ref.draft) else {}
        fp = v.get('fp') or ''

    hk_key = hostkey_key(ref.cls, ref.f)
    seen = []

    def scan(ctx, job, where):
        host, port = _where(where)
        try:
            from acmelib.certs import dnssets
            text = runtime.keyscan(dnssets.ssh_address(ctx, host), port, 10)
        except Exception as e:                          # noqa: BLE001
            job.step('no host key could be read from %s: %s' % (where, e), 'warn')
            return
        prints = ', '.join(runtime.hostkey_fingerprint(x) for x in runtime.hostkey_lines(text))
        job.step('%s shows the host key(s) %s' % (where, prints))
        seen.append((host, port, text))

    def fn(job):
        if ref.family == 'target' and ref.row and keep_hostkey:
            ctx = deployer.target_context(store, job, ref.row)
        else:
            ctx = runtime.RunContext(store, job, scope='%s:%s' % (ref.family, ref.name))
        said = []
        try:
            obj = ref.cls(cfg, ctx)
            reach = list(sessions(obj, ref.family, ref.f))
            for where, _opener in reach:
                scan(ctx, job, where)
            for where, opener in reach:
                job.step('reaching %s over SSH' % where)
                with opener() as s:
                    rc, out, err = s.run(command, timeout=30, check=False)
                    how = ('the key %s' % fp if fp else 'the key') if '-i' in s.opts else \
                        'a password'
                    job.step('signed in to %s as %s with %s' % (s.host, s.user, how), 'ok')
                    lines = [x.strip() for x in (out or err or '').splitlines() if x.strip()]
                    words = ' / '.join(lines[:4])[:300] or 'it answered, and said nothing'
                    job.step('%s said: %s' % (command, words), 'ok' if rc == 0 else 'warn')
                    said.append('%s: %s' % (s.host, words))
            job.step('nothing was written and nothing was changed', 'ok')
            return True, '; '.join(said) or 'it answered'
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'test', fn, target=ref.name if ref.family == 'target' else None,
                       by=by, said='SSH sign-in to %s' % ref.words())
    if ref.row:
        store.db.update(S.TABLE_OF[ref.family], ref.row['id'],
                        {'last_ok': time.time(), 'last_error': ''} if job.ok
                        else {'last_error': job.said[:2000]})
    # `reached`, not `ok`: an answer that it did not get in is still an answer.
    out = {'reached': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps,
           'hostkey_field': hk_key, 'hostkeys': []}
    if seen:
        out['hostkeys'] = hostkey_report(seen, cfg.get(hk_key) if hk_key else '',
                                         per_host=ref.family == 'challenge')
    return out


# ---------------------------------------------------------------------------
# What the card needs to know of this machine
# ---------------------------------------------------------------------------
def info(store):
    addrs = set()
    try:
        a = E.node_address()
        if a:
            addrs.add(a)
    except Exception:                                   # noqa: BLE001
        pass
    try:
        addrs.update(E.cluster_addresses(store, E.node_name()))
    except Exception:                                   # noqa: BLE001
        pass
    return {'can_keygen': can_keygen(), 'node': E.node_name(), 'comment': 'acme@%s' % E.node_name(),
            'from': sorted(addrs), 'key_types': sorted(KEY_TYPES)}


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------
@A.api('GET', '/api/sshkey/info')
def _info(h, s):
    return info(h.store)


@A.api('POST', '/api/sshkey/show')
def _show(h, s):
    return key_view(h.store, Ref(h.store, h.body()))


@A.api('POST', '/api/sshkey/make', 'fulladmin')
def _make(h, s):
    got = do_make(h.store, h.body(), A.who(s))
    got['message'] = 'a new key was made'
    return got


@A.api('POST', '/api/sshkey/use_own', 'fulladmin')
def _use_own(h, s):
    got = do_use_own(h.store, h.body(), A.who(s))
    got['message'] = 'the key was stored'
    return got


@A.api('POST', '/api/sshkey/forget', 'fulladmin')
def _forget(h, s):
    return do_forget(h.store, h.body(), A.who(s))


@A.api('POST', '/api/sshkey/download')
def _download(h, s):
    return do_download(h.store, h.body(), s)


@A.api('POST', '/api/sshkey/try', 'certadmin')
def _try(h, s):
    return do_try(h.store, h.body(), A.who(s))


install()


# ---------------------------------------------------------------------------
# The command line: acme --target-key NAME WHAT, --validation-key NAME WHAT
# ---------------------------------------------------------------------------
CLI_WHAT = ('make', 'show', 'public', 'own', 'private', 'forget', 'try')


def cli(c, family, words):
    """What the key card does, from the command line (acmelib/certs/cli.py's Cli
    is `c`): the same functions, as the command line's full administrator."""
    words = list(words or [])
    if len(words) < 2 or words[1] not in CLI_WHAT:
        raise SystemExit('acme: --%s-key NAME %s' % (FAMILY_WORDS[family], '|'.join(CLI_WHAT)))
    name, what, more = words[0], words[1], words[2:]
    row = c.fam_row(family, name)
    cls = S.plugin_class(family, row.get('kind'))
    if not sshkey_fields(cls):
        raise SystemExit('acme: %s (%s) signs in with no SSH key' % (name, row.get('kind')))
    b = {'family': family, 'id': row['id']}
    by = c.WHO
    store = c.store

    def shown(v):
        if c.json:
            c.out(v)
            return 0
        if not v.get('has'):
            print('  no key yet - make one (--%s-key %s make), or let it sign in with a '
                  'password' % (FAMILY_WORDS[family], name))
            return 0
        c.kv([('the key', '%s %s' % (v.get('type') or '', v.get('fp') or '')),
              ('how', {'made': 'made here', 'own': 'your own, given here'}.get(
                  v.get('how'), 'your own key, pasted before')),
              ('when', _when(v.get('made'))), ('by', v.get('by')),
              ('passphrase', 'kept, sealed' if v.get('locked') else ''),
              ('public half', v.get('public'))])
        return 0

    def out_text(text, file):
        dest = c.args.out
        if not dest or dest == '-':
            sys.stdout.write(text)
            return 0
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        return c.done('written to %s' % dest, {'ok': True, 'file': dest})

    if what == 'show':
        return shown(key_view(store, Ref(store, b)))
    if what == 'make':
        if more and more[0] not in KEY_TYPES:
            raise SystemExit('acme: make ed25519 or make rsa4096')
        b['key_type'] = more[0] if more else ''
        v = do_make(store, {k: x for k, x in b.items() if x}, by)
        c.done('a new key was made - put the public half on %s' % name, v)
        return shown(v) if not c.json else 0
    if what == 'own':
        if not more:
            raise SystemExit('acme: own FILE (a private key; its passphrase from '
                             'ACME_KEY_PASSWORD)')
        text = c._read(more[0], 64000).decode('utf-8', 'replace')
        b.update(pem=text, passphrase=os.environ.get('ACME_KEY_PASSWORD', ''))
        try:
            v = do_use_own(store, b, by)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        return c.done('the key was stored', v)
    if what == 'forget':
        c.sure('forget the SSH key of %s' % name)
        return c.done('the key is gone', do_forget(store, b, by))
    if what in ('public', 'private'):
        b['half'] = what
        try:
            got = do_download(store, b, {'name': by, 'role': 'fulladmin'})
        except LookupError as e:
            raise SystemExit('acme: %s' % e)
        return out_text(got['text'], got['file'])
    got = do_try(store, b, by, keep_hostkey=True)
    if c.json:
        c.out(got)
    else:
        for step in got.get('steps') or []:
            c.echo(step)
    return 0 if got.get('reached') else 1


def _when(ts):
    if not ts:
        return ''
    try:
        return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(ts)))
    except (TypeError, ValueError):
        return ''
