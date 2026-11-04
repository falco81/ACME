# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Codes sent by mail or SMS (1.0.76)
# ---------------------------------------------------------------------------
# The second step of an administrator's sign-in, when it is not the app: a
# code mailed or sent by SMS (through a gateway, a modem or a Teltonika),
# good for a few minutes and once. Only a hash of it is kept (in the session
# of the sign-in), never the code.

# What a code is for, and the words of each (1.0.127): the administration's
# second step and checking an address or a number for it - each its own
# message in Settings → Message texts - and checking an address for anything
# else ('verify', a module's own page).
CODE_PURPOSES = {
    'verify': {'p': 'v_', 'subject': 'verify_subject', 'body': 'verify_body', 'sms': 'sms_verify',
               'warn': False, 'note': 'h_v_note', 'queue': 'verify'},
    'admin': {'p': 'a_', 'subject': 'admin_subject', 'body': 'admin_body', 'sms': 'admin_sms',
              'warn': True, 'note': 'h_a_warn', 'queue': 'code'},
    'admin_verify': {'p': 'av_', 'subject': 'admin_verify_subject', 'body': 'admin_verify_body',
                     'sms': 'admin_sms_verify', 'warn': False, 'note': 'h_av_note',
                     'queue': 'verify'},
    # The portal's own second step (1.0.40, as otp's code before the first token, 1.0.228).
    'portal': {'p': 'p_', 'subject': 'portal_subject', 'body': 'portal_body', 'sms': 'portal_sms',
               'warn': True, 'note': 'h_p_warn', 'queue': 'code'},
}


def code_purpose(purpose):
    return CODE_PURPOSES.get(purpose) or CODE_PURPOSES['verify']

CODE_TEXTS = {
    'cs': {
        'verify_subject': 'Ověření adresy: {code}',
        'verify_body': ('Kód pro ověření této adresy je\n\n    {code}\n\nZadejte ho na stránce, '
                        'kde jste o něj požádali. Platí {minutes} min.\n\n'
                        'Pokud jste o nic nežádali, zprávu smažte.\n\n-- \n{site}'),
        'sms_verify': '{code} je kód pro ověření tohoto čísla ({site}).',
        'h_v_lede': 'kód pro ověření této adresy k účtu <b>{account}</b>:',
        'h_v_lede_anon': 'kód pro ověření této adresy:',
        'h_v_hello': 'Dobrý den, {name},',
        'h_v_hello_anon': 'Dobrý den,',
        'h_v_title': 'Ověření adresy',
        'h_v_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
        'h_v_facts': 'Zadejte ho na stránce, kde jste o něj požádali. Platí {minutes} min.',
        'h_v_note': 'Pokud jste o nic nežádali, e-mail smažte – bez kódu se nic nezmění.',
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
        # The portal's second step (1.0.40): its own words.
        'portal_subject': 'Kód pro přihlášení na portál certifikátů: {code}',
        'portal_body': ('Váš kód pro přihlášení na portál certifikátů {site} je\n\n    {code}\n\n'
                        'Platí {minutes} min a jen jednou. Pokud jste se právě nepřihlašovali, '
                        'kód nikomu nesdělujte a změňte si heslo - někdo ho zná.\n\n-- \n{site}'),
        'portal_sms': '{code} je váš kód pro přihlášení na portál certifikátů ({site}). Platí '
                      '{minutes} min. Nikomu ho nesdělujte.',
        'h_p_title': 'Portál certifikátů · Přihlášení',
        'h_p_hello': 'Dobrý den, {name},', 'h_p_hello_anon': 'Dobrý den,',
        'h_p_lede': 'váš kód pro přihlášení na portál certifikátů k účtu <b>{account}</b>:',
        'h_p_lede_anon': 'váš kód pro přihlášení na portál certifikátů:',
        'h_p_facts': 'Zadejte ho na přihlašovací stránce. Platí {minutes} min a jen jednou.',
        'h_p_warn': 'Pokud jste se právě nepřihlašovali, kód nikomu nesdělujte a změňte si heslo '
                    '– někdo ho zná.',
        'h_p_foot': 'Posláno automaticky z {site}. Na tento e-mail neodpovídejte.',
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
    },
    'en': {
        'verify_subject': 'Checking this address: {code}',
        'verify_body': ('The code to check this address is\n\n    {code}\n\nType it on the page '
                        'where you asked for it. It is good for {minutes} min.'
                        '\n\nIf you asked for nothing, delete this mail.\n\n-- \n{site}'),
        'sms_verify': '{code} is the code to check this number ({site}).',
        'h_v_lede': 'the code to check this address for <b>{account}</b>:',
        'h_v_lede_anon': 'the code to check this address:',
        'h_v_hello': 'Hello {name},',
        'h_v_hello_anon': 'Hello,',
        'h_v_title': 'Checking an address',
        'h_v_foot': 'Sent automatically by {site}. Do not reply to this mail.',
        'h_v_facts': 'Type it on the page where you asked for it. It is good for {minutes} min.',
        'h_v_note': 'If you asked for nothing, delete this mail - without the code nothing '
                    'changes.',
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
        'portal_subject': 'Your code to sign in to the certificate portal: {code}',
        'portal_body': ('Your code to sign in to the certificate portal of {site} is\n\n    {code}\n\n'
                        'It is good for {minutes} min and once. If you are not signing in just '
                        'now, tell nobody the code and change your password - somebody knows '
                        'it.\n\n-- \n{site}'),
        'portal_sms': '{code} is your code to sign in to the certificate portal ({site}). Good for '
                      '{minutes} min. Tell nobody.',
        'h_p_title': 'Certificate portal · Signing in',
        'h_p_hello': 'Hello {name},', 'h_p_hello_anon': 'Hello,',
        'h_p_lede': 'your code to sign in to the certificate portal as <b>{account}</b>:',
        'h_p_lede_anon': 'your code to sign in to the certificate portal:',
        'h_p_facts': 'Type it on the sign-in page. It is good for {minutes} min and once.',
        'h_p_warn': 'If you are not signing in just now, tell nobody the code and change your '
                    'password - somebody knows it.',
        'h_p_foot': 'Sent automatically by {site}. Do not reply to this mail.',
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
    },
}


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
    """What the pages may say of where a code went."""
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


def code_channels(conf=None):
    """Which ways of sending can be used at all - set up, not switched off."""
    c = CONFIG if conf is None else conf
    out = []
    if (c.get('mail_mode') or 'off') != 'off' and c.get('mail_from'):
        out.append('mail')
    mode = c.get('sms_mode') or 'off'
    if (mode == 'http' and c.get('sms_url')) or \
            (mode == 'spool' and c.get('sms_spool_dir')) or \
            (mode == 'teltonika' and c.get('sms_tel_host')):
        out.append('sms')
    return out


# A one-time code at every sign-in to the portal (1.0.40; otp's code before the first token,
# 1.0.228, asked here at every sign-in): which ways, in order.
PORTAL_CODE_WAYS = {'mail': ('mail',), 'sms': ('sms',), 'sms_mail': ('sms', 'mail'),
                    'mail_sms': ('mail', 'sms')}
PORTAL_CODE_KEYS = ('portal_code', 'mail_mode', 'mail_from', 'sms_mode', 'sms_url',
                    'sms_spool_dir', 'sms_tel_host', 'portal')


def portal_code_problem(conf=None):
    """Why "a one-time code at every sign-in" cannot work with these settings, or ''."""
    c = CONFIG if conf is None else conf
    ways = PORTAL_CODE_WAYS.get(str(c.get('portal_code') or 'off'))
    if not ways:
        return ''
    have = code_channels(c)
    if not any(w in have for w in ways):
        if len(ways) > 1:
            return ('a one-time code at every sign-in needs the mail (Settings → Mail) or '
                    'the SMS gateway (Settings → Codes by e-mail and SMS) set up first')
        if ways[0] == 'mail':
            return 'a one-time code at every sign-in by e-mail needs the mail (Settings → Mail) set up first'
        return ('a one-time code at every sign-in by SMS needs the SMS gateway (Settings → Codes by '
                'e-mail and SMS) set up first')
    return ''



