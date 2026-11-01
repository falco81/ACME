# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Codes sent by mail or SMS, and the VPN's second window (1.0.76)
# ---------------------------------------------------------------------------
# A token is one of three kinds:
#   totp  - the authenticator app, as it always was (the kind column empty);
#   mail  - no app: after the directory password a code is mailed;
#   sms   - the same, by SMS through a gateway or a modem.
# A mail or SMS token holds no key anybody scans - only where the codes go
# (`dest`) and its recovery codes. It signs in through RADIUS
# Challenge/Response: the first Access-Request carries the directory
# password; it is checked (and the groups), a code is sent and an
# Access-Challenge goes back with a State; the VPN (Cisco Secure Client and
# others) shows a second window, and the code comes back in a second
# Access-Request with that State.
#
# A challenge is kept in the database (meta 'chal:' + hash of the State), so
# that the answer is taken by either node of a cluster. It holds a hash of
# the code, never the code.

CODE_KINDS = ('totp', 'mail', 'sms')
CODE_KIND_WORDS = {'totp': 'the authenticator app', 'mail': 'a code by mail',
                   'sms': 'a code by SMS'}
CHAL_PREFIX = b'acme1'
# What a code is for, and the words of each (1.0.127): the VPN's sign-in and
# checking an address for it, and the same two for the administration's
# second step - each its own message in Settings → Message texts.
CODE_PURPOSES = {
    'signin': {'p': '', 'subject': 'mail_subject', 'body': 'mail_body', 'sms': 'sms',
               'warn': True, 'note': 'h_warn', 'queue': 'code'},
    'verify': {'p': 'v_', 'subject': 'verify_subject', 'body': 'verify_body', 'sms': 'sms_verify',
               'warn': False, 'note': 'h_v_note', 'queue': 'verify'},
    'admin': {'p': 'a_', 'subject': 'admin_subject', 'body': 'admin_body', 'sms': 'admin_sms',
              'warn': True, 'note': 'h_a_warn', 'queue': 'code'},
    'admin_verify': {'p': 'av_', 'subject': 'admin_verify_subject', 'body': 'admin_verify_body',
                     'sms': 'admin_sms_verify', 'warn': False, 'note': 'h_av_note',
                     'queue': 'verify'},
    # Signing in over SSH to the nodes (1.0.181): words of its own.
    'ssh': {'p': 's_', 'subject': 'ssh_subject', 'body': 'ssh_body', 'sms': 'ssh_sms',
            'warn': True, 'note': 'h_s_warn', 'queue': 'code'},
}


def code_purpose(purpose):
    return CODE_PURPOSES.get(purpose) or CODE_PURPOSES['verify']

CODE_TEXTS = {
    'cs': {
        'mail_subject': 'Kód pro přihlášení: {code}',
        'mail_body': ('Váš kód pro přihlášení je\n\n    {code}\n\nPlatí {minutes} min a jen '
                      'jednou. Pokud jste se právě nepřihlašovali, kód nikomu nesdělujte a '
                      'změňte si heslo - někdo ho zná.\n\n-- \n{site}'),
        'verify_subject': 'Ověření adresy: {code}',
        'verify_body': ('Kód pro ověření této adresy je\n\n    {code}\n\nZadejte ho na stránce, '
                        'kde jste si nastavovali přihlašování. Platí {minutes} min.\n\n'
                        'Pokud jste o nic nežádali, zprávu smažte.\n\n-- \n{site}'),
        'sms': '{code} je váš kód pro přihlášení ({site}). Platí {minutes} min. Nikomu ho '
               'nesdělujte.',
        'sms_verify': '{code} je kód pro ověření tohoto čísla ({site}).',
        'h_hello': 'Dobrý den, {name},',
        'h_hello_anon': 'Dobrý den,',
        'h_lede': 'váš kód pro přihlášení do VPN k účtu <b>{account}</b>:',
        'h_lede_anon': 'váš kód pro přihlášení do VPN:',
        'h_facts': 'Zadejte ho do druhého okna VPN. Platí {minutes} min a jen jednou.',
        'h_warn': 'Pokud jste se právě nepřihlašovali, kód nikomu nesdělujte a změňte si heslo '
                  '– někdo ho zná.',
        'h_v_lede': 'kód pro ověření této adresy pro přihlašování do VPN k účtu <b>{account}</b>:',
        'h_v_lede_anon': 'kód pro ověření této adresy pro přihlašování do VPN:',
        'h_v_hello': 'Dobrý den, {name},',
        'h_v_hello_anon': 'Dobrý den,',
        'h_v_title': 'VPN · Dvoufázové přihlášení',
        'h_v_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'h_v_facts': 'Zadejte ho na stránce, kde si nastavujete přihlašování. Platí {minutes} min.',
        'h_v_note': 'Pokud jste o nic nežádali, e-mail smažte – bez kódu se nic nezmění.',
        'h_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'h_title': 'VPN · Dvoufázové přihlášení',
        # The administration's second step (1.0.127): its own words.
        'admin_subject': 'Kód pro přihlášení do administrace: {code}',
        'admin_body': ('Váš kód pro přihlášení do administrace {site} je\n\n    {code}\n\n'
                       'Platí {minutes} min a jen jednou. Pokud jste se právě nepřihlašovali, '
                       'kód nikomu nesdělujte a změňte si heslo - někdo ho zná.\n\n-- \n{site}'),
        'admin_verify_subject': 'Ověření adresy pro administraci: {code}',
        'admin_verify_body': ('Kód pro ověření této adresy pro přihlašování do administrace '
                              '{site} je\n\n    {code}\n\nZadejte ho na přihlašovací stránce '
                              'administrace. Platí {minutes} min.\n\nPokud jste o nic '
                              'nežádali, zprávu smažte.\n\n-- \n{site}'),
        'admin_sms': '{code} je váš kód pro přihlášení do administrace ({site}). Platí {minutes} '
                     'min. Nikomu ho nesdělujte.',
        'admin_sms_verify': '{code} je kód pro ověření tohoto čísla pro administraci ({site}).',
        'h_a_title': 'Administrace · Druhý krok přihlášení',
        'h_a_hello': 'Dobrý den, {name},', 'h_a_hello_anon': 'Dobrý den,',
        'h_a_lede': 'váš kód pro přihlášení do administrace k účtu <b>{account}</b>:',
        'h_a_lede_anon': 'váš kód pro přihlášení do administrace:',
        'h_a_facts': 'Zadejte ho na přihlašovací stránce administrace. Platí {minutes} min a jen '
                     'jednou.',
        'h_a_warn': 'Pokud jste se právě nepřihlašovali, kód nikomu nesdělujte a změňte si heslo '
                    '– někdo ho zná.',
        'h_a_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'h_av_title': 'Administrace · Druhý krok přihlášení',
        'h_av_hello': 'Dobrý den, {name},', 'h_av_hello_anon': 'Dobrý den,',
        'h_av_lede': 'kód pro ověření této adresy pro přihlašování do administrace k účtu '
                     '<b>{account}</b>:',
        'h_av_lede_anon': 'kód pro ověření této adresy pro přihlašování do administrace:',
        'h_av_facts': 'Zadejte ho na přihlašovací stránce administrace. Platí {minutes} min.',
        'h_av_note': 'Pokud jste o nic nežádali, e-mail smažte – bez kódu se nic nezmění.',
        'h_av_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'ssh_ask_app': 'Kód z aplikace',
        'ssh_subject': 'Kód pro přihlášení přes SSH: {code}',
        'ssh_body': ('Váš kód pro přihlášení přes SSH na server {site} je\n\n    {code}\n\nPlatí '
                     '{minutes} min a jen jednou. Pokud se právě nepřihlašujete, kód nikomu '
                     'nesdělujte - někdo zkouší váš účet.\n\n-- \n{site}'),
        'ssh_sms': '{code} je váš kód pro přihlášení přes SSH ({site}). Platí {minutes} min. '
                   'Nikomu ho nesdělujte.',
        'h_s_title': 'SSH · Přihlášení s kódem',
        'h_s_hello': 'Dobrý den, {name},', 'h_s_hello_anon': 'Dobrý den,',
        'h_s_lede': 'váš kód pro přihlášení přes SSH k účtu <b>{account}</b>:',
        'h_s_lede_anon': 'váš kód pro přihlášení přes SSH:',
        'h_s_facts': 'Zadejte ho tam, kde se SSH ptá na kód. Platí {minutes} min a jen jednou.',
        'h_s_warn': 'Pokud se právě nepřihlašujete, kód nikomu nesdělujte – někdo zkouší váš účet.',
        'h_s_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'ask_mail': 'Zadejte kód, který přišel e-mailem na {dest}',
        'ask_sms': 'Zadejte kód z SMS poslané na {dest}',
        'ask_totp': 'Zadejte kód z aplikace v telefonu',
        'again': 'Kód nebyl správný - zadejte ho znovu',
    },
    'en': {
        'mail_subject': 'Your sign-in code: {code}',
        'mail_body': ('Your sign-in code is\n\n    {code}\n\nIt is good for {minutes} min and '
                      'once. If you are not signing in just now, tell nobody the code and '
                      'change your password - somebody knows it.\n\n-- \n{site}'),
        'verify_subject': 'Checking this address: {code}',
        'verify_body': ('The code to check this address is\n\n    {code}\n\nType it on the page '
                        'where you are setting up your sign-in. It is good for {minutes} min.'
                        '\n\nIf you asked for nothing, delete this mail.\n\n-- \n{site}'),
        'sms': '{code} is your sign-in code ({site}). Good for {minutes} min. Tell nobody.',
        'sms_verify': '{code} is the code to check this number ({site}).',
        'h_hello': 'Hello {name},',
        'h_hello_anon': 'Hello,',
        'h_lede': 'your code to sign in to the VPN as <b>{account}</b>:',
        'h_lede_anon': 'your code to sign in to the VPN:',
        'h_facts': 'Type it into the VPN\'s second window. It is good for {minutes} min and once.',
        'h_warn': 'If you are not signing in just now, tell nobody the code and change your '
                  'password - somebody knows it.',
        'h_v_lede': 'the code to check this address for signing in to the VPN as <b>{account}</b>:',
        'h_v_lede_anon': 'the code to check this address for signing in to the VPN:',
        'h_v_hello': 'Hello {name},',
        'h_v_hello_anon': 'Hello,',
        'h_v_title': 'VPN · Two-step sign-in',
        'h_v_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'h_v_facts': 'Type it on the page where you are setting up your sign-in. It is good for '
                     '{minutes} min.',
        'h_v_note': 'If you asked for nothing, delete this mail - without the code nothing '
                    'changes.',
        'h_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'h_title': 'VPN · Two-step sign-in',
        'admin_subject': 'Your code for the administration: {code}',
        'admin_body': ('Your code to sign in to the administration of {site} is\n\n    {code}\n\n'
                       'It is good for {minutes} min and once. If you are not signing in just '
                       'now, tell nobody the code and change your password - somebody knows '
                       'it.\n\n-- \n{site}'),
        'admin_verify_subject': 'Checking this address for the administration: {code}',
        'admin_verify_body': ('The code to check this address for signing in to the '
                              'administration of {site} is\n\n    {code}\n\nType it on the '
                              'administration\'s sign-in page. It is good for {minutes} min.'
                              '\n\nIf you asked for nothing, delete this mail.\n\n-- \n{site}'),
        'admin_sms': '{code} is your code for the administration ({site}). Good for {minutes} '
                     'min. Tell nobody.',
        'admin_sms_verify': '{code} is the code to check this number for the administration '
                            '({site}).',
        'h_a_title': 'Administration · Second step',
        'h_a_hello': 'Hello {name},', 'h_a_hello_anon': 'Hello,',
        'h_a_lede': 'your code to sign in to the administration as <b>{account}</b>:',
        'h_a_lede_anon': 'your code to sign in to the administration:',
        'h_a_facts': 'Type it on the administration\'s sign-in page. It is good for {minutes} min '
                     'and once.',
        'h_a_warn': 'If you are not signing in just now, tell nobody the code and change your '
                    'password - somebody knows it.',
        'h_a_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'h_av_title': 'Administration · Second step',
        'h_av_hello': 'Hello {name},', 'h_av_hello_anon': 'Hello,',
        'h_av_lede': 'the code to check this address for signing in to the administration as '
                     '<b>{account}</b>:',
        'h_av_lede_anon': 'the code to check this address for signing in to the administration:',
        'h_av_facts': 'Type it on the administration\'s sign-in page. It is good for {minutes} '
                      'min.',
        'h_av_note': 'If you asked for nothing, delete this mail - without the code nothing '
                     'changes.',
        'h_av_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'ssh_ask_app': 'Code from the app',
        'ssh_subject': 'Your SSH sign-in code: {code}',
        'ssh_body': ('Your code for signing in over SSH to {site} is\n\n    {code}\n\nIt is good '
                     'for {minutes} min and once. If you are not signing in just now, tell '
                     'nobody the code - somebody is trying your account.\n\n-- \n{site}'),
        'ssh_sms': '{code} is your SSH sign-in code ({site}). Good for {minutes} min. Tell nobody.',
        'h_s_title': 'SSH · Signing in with a code',
        'h_s_hello': 'Hello {name},', 'h_s_hello_anon': 'Hello,',
        'h_s_lede': 'your code for signing in over SSH as <b>{account}</b>:',
        'h_s_lede_anon': 'your code for signing in over SSH:',
        'h_s_facts': 'Type it where SSH asks for the code. It is good for {minutes} min and once.',
        'h_s_warn': 'If you are not signing in just now, tell nobody the code - somebody is '
                    'trying your account.',
        'h_s_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'ask_mail': 'Type the code mailed to {dest}',
        'ask_sms': 'Type the code sent by SMS to {dest}',
        'ask_totp': 'Type the code from the app on your phone',
        'again': 'That code was not right - type it again',
    },
}


def token_lang(tok):
    """The language a token's codes and questions are in (1.0.82): its own,
    else the setting's."""
    lang = str((tok or {}).get('lang') or '')
    return lang if lang in CODE_TEXTS else code_lang()


def token_mail_fmt(tok):
    fmt = str((tok or {}).get('mail_fmt') or '')
    if fmt in ('html', 'text'):
        return fmt
    return 'text' if CONFIG.get('code_mail_fmt') == 'text' else 'html'


def code_lang():
    lang = str(CONFIG.get('code_lang') or CONFIG.get('mail_lang') or 'cs')
    return lang if lang in CODE_TEXTS else 'cs'


def code_words(key, lang=None, w=None, **kw):
    """One of the texts of codes, as Settings → Message texts has it
    (1.0.103), its {words} filled in."""
    if w is None:
        w = texts_for('code', lang if lang in CODE_TEXTS else code_lang())
    kw.setdefault('site', str(CONFIG.get('site_name') or socket.gethostname()))
    kw.setdefault('minutes', max(1, int(CONFIG.get('code_ttl_s') or 300) // 60))
    return w[key].format(**kw)


def token_kind(tok):
    k = str((tok or {}).get('kind') or '').strip().lower()
    return k if k in ('mail', 'sms') else 'totp'


def mail_checked(dest):
    dest = str(dest or '').strip()
    if not re.match(r'^[^@\s<>,;"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}\Z', dest):
        raise ValueError('that is not a mail address')
    return dest


def phone_checked(dest):
    """A number as +CCCNNN…: spaces, dashes and brackets taken out, the
    country code of the settings put before a number written without one."""
    raw = re.sub(r'[\s().\-/]', '', str(dest or ''))
    if raw.startswith('00'):
        raw = '+' + raw[2:]
    if not raw.startswith('+'):
        pre = str(CONFIG.get('sms_prefix') or '').strip()
        if not pre:
            raise ValueError('write the number with its country code: +420 603 123 456')
        digits = raw.lstrip('0')
        # 420603123456 written without its + (1.0.146): not +420420603123456.
        # Not a number dialled at home with its 0 (1.0.147): 0491 12345678
        # in Germany is 491..., and is not +49 1 12345678.
        if not raw.startswith('0') and pre.lstrip('+') and digits.startswith(pre.lstrip('+')) and \
                len(digits) - len(pre.lstrip('+')) >= 8:
            raw = '+' + digits
        else:
            raw = pre + digits
    if not re.match(r'^\+[1-9][0-9]{7,14}\Z', raw):
        raise ValueError('that is not a phone number - write it as +420 603 123 456')
    return raw


def dest_checked(kind, dest):
    if kind == 'mail':
        return mail_checked(dest)
    if kind == 'sms':
        return phone_checked(dest)
    return ''


def dest_masked(kind, dest):
    """What the VPN and the pages may say of where a code went."""
    dest = str(dest or '')
    if kind == 'mail' and '@' in dest:
        who, _, where = dest.partition('@')
        return '%s%s@%s' % (who[:1], '*' * max(2, min(len(who) - 1, 6)), where)
    if kind == 'sms' and len(dest) > 4:
        return '%s%s%s' % (dest[:4], '*' * (len(dest) - 7), dest[-3:])
    return dest


def code_new():
    digits = int(CONFIG.get('code_digits') or 6)
    return '%0*d' % (digits, secrets.randbelow(10 ** digits))


def code_hash(salt, code):
    key = sealing_key() or b''
    return hmac.new(key + b'|code', ('%s|%s' % (salt, code)).encode('utf-8'),
                    hashlib.sha256).hexdigest()


def code_channels():
    """Which ways of sending can be used at all - set up, not switched off."""
    out = []
    if (CONFIG.get('mail_mode') or 'off') != 'off' and CONFIG.get('mail_from'):
        out.append('mail')
    mode = CONFIG.get('sms_mode') or 'off'
    if (mode == 'http' and CONFIG.get('sms_url')) or \
            (mode == 'spool' and CONFIG.get('sms_spool_dir')) or \
            (mode == 'teltonika' and CONFIG.get('sms_tel_host')):
        out.append('sms')
    return out


def realm_methods(realm):
    """The kinds of token a realm offers, in the order given; the app when
    nothing is said (every realm made before 1.0.76)."""
    raw = (realm or {}).get('methods')
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip().startswith('[') else re.split(r'[,\s]+', raw)
        except ValueError:
            raw = []
    got = [str(x).strip().lower() for x in (raw or []) if str(x).strip().lower() in CODE_KINDS]
    seen = []
    for k in got:
        if k not in seen:
            seen.append(k)
    return seen or ['totp']


