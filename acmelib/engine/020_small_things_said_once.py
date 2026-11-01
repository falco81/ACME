# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Small things, said once
# ---------------------------------------------------------------------------
def now():
    return time.time()


def human_span(seconds):
    s = max(0, int(seconds or 0))
    if s < 60:
        return '%d s' % s
    if s < 3600:
        return '%d min' % (s // 60)
    if s < 86400:
        return '%d h %d min' % (s // 3600, (s % 3600) // 60)
    days = s // 86400
    return '%s %d h' % ('1 day' if days == 1 else '%d days' % days, (s % 86400) // 3600)


def stamp(ts):
    if not ts:
        return '-'
    return datetime.fromtimestamp(float(ts)).strftime('%d-%m-%Y %H:%M:%S')


def short_host():
    try:
        return socket.gethostname().split('.')[0] or 'acme'
    except OSError:
        return 'acme'


# Letters beyond ASCII a name takes (1.0.154, split in 1.0.155): Czech's and
# Slovak's with names_czsk_letters, every language's with names_any_letters;
# both off, none.
NAME_LETTERS_HOME = set('áäčďéěíĺľňóôŕřšťúůýž' + 'áäčďéěíĺľňóôŕřšťúůýž'.upper())


def name_letters_problem(name):
    """'' when the name's letters are ones this server takes, else what is
    wrong with it, in words."""
    if CONFIG.get('names_any_letters'):
        return ''
    import unicodedata
    said = unicodedata.normalize('NFC', str(name or ''))
    home = bool(CONFIG.get('names_czsk_letters'))
    odd = sorted({c for c in said if ord(c) > 127 and not (home and c in NAME_LETTERS_HOME)})
    if not odd:
        return ''
    if home:
        return ('the name %s has letters of another language (%s) - only Czech and Slovak ones '
                'are taken (Settings - Accounts - Letters of other languages in names)'
                % (said[:60], ' '.join(odd[:8])))
    return ('the name %s has letters with accents or of another language (%s) - only letters '
            'without accents are taken (Settings - Accounts - Czech and Slovak letters in '
            'names, Letters of other languages in names)' % (said[:60], ' '.join(odd[:8])))


def dn_list(text):
    """Group names or DNs out of one setting: split on semicolons and new
    lines, never on commas - a DN is mostly commas."""
    if isinstance(text, (list, tuple)):
        pieces = list(text)
    else:
        pieces = re.split(r'[;\n]', str(text or ''))
    return [p.strip() for p in pieces if str(p).strip()]


def cn_of(dn):
    """`CN=VPN Users,OU=Groups,...` as `VPN Users`; a plain name as itself."""
    said = str(dn or '').strip()
    m = re.match(r'(?i)^cn=((?:\\.|[^,])*)', said)
    if m:
        return re.sub(r'\\(.)', r'\1', m.group(1)).strip()
    return said


def password_hash(password, salt=None, rounds=310000):
    salt = salt or secrets.token_bytes(16)
    got = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt, rounds)
    return 'pbkdf2_sha256$%d$%s$%s' % (rounds, base64.b64encode(salt).decode('ascii'),
                                       base64.b64encode(got).decode('ascii'))


def password_ok(password, stored):
    try:
        kind, rounds, salt, want = str(stored or '').split('$')
        if kind != 'pbkdf2_sha256':
            return False
        got = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'),
                                  base64.b64decode(salt), int(rounds))
        return hmac.compare_digest(got, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


def password_problem(password):
    """Why a password for an account here will not do, or ''."""
    p = str(password or '')
    if len(p) < 8:
        return 'a password needs at least eight characters'
    if len(p) > 200:
        return 'that password is longer than anybody types'
    return ''


