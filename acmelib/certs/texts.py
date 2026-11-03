# -*- coding: utf-8 -*-
"""
The words of the certificate manager's notifications - mails and SMS - in
English and Czech, put into the engine's registry of message texts by engine
part 900 (TEXT_MESSAGES, TEXT_GROUPS['certs'], TEXT_PLACEHOLDERS,
TEXT_SAMPLES), so Settings → Message texts edits them as every other, both
nodes of a cluster send the same words, and a text put back is as it comes.

    draw(mid, lang, values) -> {'subject', 'html', 'text'} | {'sms'}

draws one message with real values (notices.py sends it); render() is the
same for the editor's preview, with its sample values and its marks.

Placeholders: {cert} {names} {left} {not_after} {issuer} {serial} {version}
{error} {retry} {target} {node} {site} {name} {reason}.
"""
from __future__ import annotations

import html as _html
import string
import time

GROUP = 'certs'

PLACEHOLDERS = {
    'cert': 'the certificate’s name in acme', 'names': 'the names in it',
    'left': 'how long it has left', 'not_after': 'when it ends',
    'issuer': 'where it comes from', 'serial': 'its serial number',
    'version': 'its version in acme', 'error': 'what went wrong',
    'retry': 'when it is tried again', 'target': 'where it was deployed',
    'node': 'the node that did it', 'reason': 'why',
    'check': 'the test (its kind and address)',
}
SAMPLES = {
    'cert': 'www', 'names': 'www.example.cz, example.cz', 'left': '9 days',
    'not_after': '2026-12-01 12:00 UTC', 'issuer': "Let's Encrypt",
    'serial': '04:A1:9C:55:2E:0B', 'version': 7,
    'error': 'the CA refused the order: rateLimited', 'retry': '20 min',
    'target': 'f5-prague', 'node': 'acme1', 'reason': 'the names are not ours',
    'check': 'HTTPS www.example.cz:443',
}

# (id, the words of its kind, what it is said for, the placeholders it can
#  have, the tone of its band: bad | warn | ok, an SMS too)
EVENTS = [
    ('cert_expiring', 'A certificate ends soon',
     'Sent when a certificate ends within certs_notify_days and nothing renews it by itself '
     '(or its renewal keeps failing).',
     ('cert', 'names', 'left', 'not_after', 'issuer', 'serial', 'node', 'site'), 'warn', True),
    ('cert_expired', 'A certificate has expired',
     'Sent once when a certificate has run out.',
     ('cert', 'names', 'not_after', 'issuer', 'serial', 'node', 'site'), 'bad', True),
    ('cert_renewed', 'A certificate renewed',
     'Sent after a renewal (or the first issue), when Settings → Certificates says to tell '
     'what went well too (certs_notify_ok).',
     ('cert', 'names', 'version', 'not_after', 'issuer', 'serial', 'node', 'site'), 'ok', True),
    ('cert_renew_failed', 'Renewing a certificate failed',
     'Sent when a renewal fails (at most every 6 hours for one certificate).',
     ('cert', 'names', 'error', 'retry', 'not_after', 'left', 'issuer', 'node', 'site'), 'bad',
     True),
    ('cert_deployed', 'A certificate deployed',
     'Sent after a deployment went well, when Settings → Certificates says to tell what went '
     'well too (certs_notify_ok).',
     ('cert', 'names', 'target', 'version', 'not_after', 'serial', 'node', 'site'), 'ok', True),
    ('cert_deploy_failed', 'Deploying a certificate failed',
     'Sent when putting a certificate on a target fails (at most every 6 hours for one '
     'deployment).',
     ('cert', 'names', 'target', 'error', 'retry', 'version', 'node', 'site'), 'bad', True),
    ('cert_check_failed', 'A test of a server failed',
     'Sent when a test of a deployment starts failing - the server serves an old or another '
     'certificate, or cannot be reached (at most every 6 hours for one test).',
     ('cert', 'names', 'target', 'check', 'error', 'version', 'node', 'site'), 'bad', True),
    ('cert_check_ok', 'A test of a server works again',
     'Sent when a test that failed works again.',
     ('cert', 'names', 'target', 'check', 'version', 'node', 'site'), 'ok', True),
    ('cert_portal_issued', 'The enrolment pages: a certificate issued',
     'Sent to the person who asked for a certificate on the enrolment pages, once it is '
     'issued.',
     ('cert', 'names', 'not_after', 'issuer', 'name', 'site'), 'ok', False),
    ('cert_portal_declined', 'The enrolment pages: a request declined',
     'Sent to the person who asked for a certificate on the enrolment pages, when it is '
     'declined.',
     ('cert', 'names', 'reason', 'name', 'site'), 'bad', False),
]


def _p(mid):
    return mid[len('cert_'):] if mid.startswith('cert_') else mid


def mail_fields(mid, ph):
    p = 'c_' + _p(mid)
    return [(p + '_subject', 'line', 'Subject', ph, 'subject'),
            (p + '_title', 'line', 'The band at the top', ('site', 'node'), 'layout'),
            (p + '_lede', 'rich', 'What happened', ph, 'layout'),
            (p + '_note', 'rich', 'What to do', ph, 'layout'),
            (p + '_foot', 'rich', 'The foot', ('site', 'node'), 'layout'),
            (p + '_body', 'text', 'The plain text version', ph, 'plain')]


def sms_fields(mid, ph):
    return [('c_' + _p(mid) + '_sms', 'text', 'The SMS', ph, 'sms')]


W = {'en': {}, 'cs': {}}


def _put(mid, lang, subject, title, lede, note, foot, body, sms=None):
    p = 'c_' + _p(mid)
    W[lang].update({p + '_subject': subject, p + '_title': title, p + '_lede': lede,
                    p + '_note': note, p + '_foot': foot, p + '_body': body})
    if sms is not None:
        W[lang][p + '_sms'] = sms


FOOT_EN = 'Sent by acme on {node} - {site}. Who is told is set on Settings → Certificates.'
FOOT_CS = 'Poslal acme na {node} - {site}. Komu se to posílá, je v Nastavení → Certifikáty.'

_put('cert_expiring', 'en', 'Certificate {cert} ends in {left}', '{site}: a certificate ends soon',
     'The certificate <b>{cert}</b> ({names}) ends in <b>{left}</b>, on {not_after}, and nothing '
     'renews it by itself.',
     'Renew it (Certificates → {cert} → Renew), or switch on renewing it by itself.', FOOT_EN,
     'The certificate {cert} ({names}) ends in {left}, on {not_after}, and nothing renews it '
     'by itself.\n\nRenew it, or switch on renewing it by itself.\n\n-- acme on {node}',
     'acme: certificate {cert} ends in {left} ({not_after}) and is not renewed by itself.')
_put('cert_expiring', 'cs', 'Certifikát {cert} končí za {left}', '{site}: certifikát brzy končí',
     'Certifikát <b>{cert}</b> ({names}) končí za <b>{left}</b>, {not_after}, a nic ho samo '
     'neobnoví.',
     'Obnovte ho (Certifikáty → {cert} → Obnovit), nebo zapněte jeho automatické obnovování.',
     FOOT_CS,
     'Certifikát {cert} ({names}) končí za {left}, {not_after}, a nic ho samo neobnoví.\n\n'
     'Obnovte ho, nebo zapněte jeho automatické obnovování.\n\n-- acme na {node}',
     'acme: certifikát {cert} končí za {left} ({not_after}) a sám se neobnoví.')
_put('cert_expired', 'en', 'Certificate {cert} has expired', '{site}: a certificate has expired',
     'The certificate <b>{cert}</b> ({names}) ended on <b>{not_after}</b>.',
     'Whatever still uses it shows an error now: renew it, or import a new one.', FOOT_EN,
     'The certificate {cert} ({names}) ended on {not_after}.\n\nWhatever still uses it shows an '
     'error now: renew it, or import a new one.\n\n-- acme on {node}',
     'acme: certificate {cert} has EXPIRED ({not_after}).')
_put('cert_expired', 'cs', 'Certifikát {cert} vypršel', '{site}: certifikát vypršel',
     'Certifikát <b>{cert}</b> ({names}) skončil <b>{not_after}</b>.',
     'Co ho ještě používá, teď hlásí chybu: obnovte ho, nebo nahrajte nový.', FOOT_CS,
     'Certifikát {cert} ({names}) skončil {not_after}.\n\nCo ho ještě používá, teď hlásí chybu: '
     'obnovte ho, nebo nahrajte nový.\n\n-- acme na {node}',
     'acme: certifikát {cert} VYPRŠEL ({not_after}).')
_put('cert_renewed', 'en', 'Certificate {cert} renewed', '{site}: a certificate renewed',
     'The certificate <b>{cert}</b> ({names}) was renewed by {issuer}: version {version}, '
     'valid until <b>{not_after}</b>.',
     'Its deployments follow by themselves.', FOOT_EN,
     'The certificate {cert} ({names}) was renewed by {issuer}: version {version}, serial '
     '{serial}, valid until {not_after}.\n\n-- acme on {node}',
     'acme: certificate {cert} renewed, valid until {not_after}.')
_put('cert_renewed', 'cs', 'Certifikát {cert} obnoven', '{site}: certifikát obnoven',
     'Certifikát <b>{cert}</b> ({names}) obnovil {issuer}: verze {version}, platí do '
     '<b>{not_after}</b>.',
     'Jeho nasazení proběhnou sama.', FOOT_CS,
     'Certifikát {cert} ({names}) obnovil {issuer}: verze {version}, sériové číslo {serial}, '
     'platí do {not_after}.\n\n-- acme na {node}',
     'acme: certifikát {cert} obnoven, platí do {not_after}.')
_put('cert_renew_failed', 'en', 'Renewing {cert} failed', '{site}: a renewal failed',
     'Renewing the certificate <b>{cert}</b> ({names}) at {issuer} failed:<br><b>{error}</b>',
     'acme tries again in {retry}. The certificate ends on {not_after} ({left} left). The job '
     'on Certificates → Jobs has every step.', FOOT_EN,
     'Renewing the certificate {cert} ({names}) at {issuer} failed:\n{error}\n\nacme tries again '
     'in {retry}. The certificate ends on {not_after} ({left} left).\n\n-- acme on {node}',
     'acme: renewing {cert} failed: {error}')
_put('cert_renew_failed', 'cs', 'Obnovení {cert} selhalo', '{site}: obnovení selhalo',
     'Obnovení certifikátu <b>{cert}</b> ({names}) u {issuer} selhalo:<br><b>{error}</b>',
     'acme to zkusí znovu za {retry}. Certifikát končí {not_after} (zbývá {left}). Úloha v '
     'Certifikáty → Úlohy má každý krok.', FOOT_CS,
     'Obnovení certifikátu {cert} ({names}) u {issuer} selhalo:\n{error}\n\nacme to zkusí znovu za '
     '{retry}. Certifikát končí {not_after} (zbývá {left}).\n\n-- acme na {node}',
     'acme: obnovení {cert} selhalo: {error}')
_put('cert_deployed', 'en', 'Certificate {cert} deployed to {target}',
     '{site}: a certificate deployed',
     'The certificate <b>{cert}</b> (version {version}, until {not_after}) is in place on '
     '<b>{target}</b>.', 'Nothing to do.', FOOT_EN,
     'The certificate {cert} (version {version}, until {not_after}) is in place on {target}.'
     '\n\n-- acme on {node}',
     'acme: {cert} deployed to {target}.')
_put('cert_deployed', 'cs', 'Certifikát {cert} nasazen na {target}',
     '{site}: certifikát nasazen',
     'Certifikát <b>{cert}</b> (verze {version}, do {not_after}) je na <b>{target}</b>.',
     'Není co dělat.', FOOT_CS,
     'Certifikát {cert} (verze {version}, do {not_after}) je na {target}.\n\n-- acme na {node}',
     'acme: {cert} nasazen na {target}.')
_put('cert_deploy_failed', 'en', 'Deploying {cert} to {target} failed',
     '{site}: a deployment failed',
     'Putting the certificate <b>{cert}</b> (version {version}) on <b>{target}</b> failed:<br>'
     '<b>{error}</b>',
     'acme tries again in {retry}. The job on Certificates → Jobs has every step.', FOOT_EN,
     'Putting the certificate {cert} (version {version}) on {target} failed:\n{error}\n\nacme '
     'tries again in {retry}.\n\n-- acme on {node}',
     'acme: deploying {cert} to {target} failed: {error}')
_put('cert_deploy_failed', 'cs', 'Nasazení {cert} na {target} selhalo',
     '{site}: nasazení selhalo',
     'Nasazení certifikátu <b>{cert}</b> (verze {version}) na <b>{target}</b> selhalo:<br>'
     '<b>{error}</b>',
     'acme to zkusí znovu za {retry}. Úloha v Certifikáty → Úlohy má každý krok.', FOOT_CS,
     'Nasazení certifikátu {cert} (verze {version}) na {target} selhalo:\n{error}\n\nacme to '
     'zkusí znovu za {retry}.\n\n-- acme na {node}',
     'acme: nasazení {cert} na {target} selhalo: {error}')
_put('cert_check_failed', 'en', 'A test of {cert} on {target} failed',
     '{site}: a test of a server failed',
     'The test <b>{check}</b> of the certificate <b>{cert}</b> (version {version}) on '
     '<b>{target}</b> failed:<br><b>{error}</b>',
     'The server does not serve what acme deployed. Certificates → Targets → the target → '
     'Tests has what it served.', FOOT_EN,
     'The test {check} of the certificate {cert} (version {version}) on {target} failed:\n'
     '{error}\n\n-- acme on {node}',
     'acme: test {check} of {cert} on {target} failed: {error}')
_put('cert_check_failed', 'cs', 'Test {cert} na {target} selhal',
     '{site}: test serveru selhal',
     'Test <b>{check}</b> certifikátu <b>{cert}</b> (verze {version}) na <b>{target}</b> '
     'selhal:<br><b>{error}</b>',
     'Server neposílá to, co acme nasadilo. Certifikáty → Cíle → cíl → Testy ukáže, co '
     'server poslal.', FOOT_CS,
     'Test {check} certifikátu {cert} (verze {version}) na {target} selhal:\n{error}\n\n'
     '-- acme na {node}',
     'acme: test {check} certifikátu {cert} na {target} selhal: {error}')
_put('cert_check_ok', 'en', 'A test of {cert} on {target} works again',
     '{site}: a test works again',
     'The test <b>{check}</b> of <b>{cert}</b> (version {version}) on <b>{target}</b> works '
     'again: the server serves the certificate acme deployed.', 'Nothing to do.', FOOT_EN,
     'The test {check} of {cert} (version {version}) on {target} works again.\n\n-- acme on '
     '{node}',
     'acme: test {check} of {cert} on {target} works again.')
_put('cert_check_ok', 'cs', 'Test {cert} na {target} zase funguje',
     '{site}: test zase funguje',
     'Test <b>{check}</b> certifikátu <b>{cert}</b> (verze {version}) na <b>{target}</b> zase '
     'funguje: server posílá certifikát, který acme nasadilo.', 'Není co dělat.', FOOT_CS,
     'Test {check} certifikátu {cert} (verze {version}) na {target} zase funguje.\n\n-- acme '
     'na {node}',
     'acme: test {check} certifikátu {cert} na {target} zase funguje.')
_put('cert_portal_issued', 'en', 'Your certificate {cert} is ready', '{site}: your certificate',
     'Hello {name}, the certificate you asked for, <b>{cert}</b> ({names}), is issued by '
     '{issuer} and valid until {not_after}.',
     'Download it on the enrolment pages, under Certificates. It is renewed by itself.',
     'Sent by acme - {site}.',
     'Hello {name},\n\nthe certificate you asked for, {cert} ({names}), is issued by {issuer} '
     'and valid until {not_after}. Download it on the enrolment pages, under Certificates.\n\n'
     '-- {site}')
_put('cert_portal_issued', 'cs', 'Váš certifikát {cert} je připraven', '{site}: váš certifikát',
     'Dobrý den, {name}, certifikát, o který jste požádali, <b>{cert}</b> ({names}), vydal '
     '{issuer} a platí do {not_after}.',
     'Stáhnete si ho na zápisových stránkách, v části Certifikáty. Obnovuje se sám.',
     'Poslal acme - {site}.',
     'Dobrý den, {name},\n\ncertifikát, o který jste požádali, {cert} ({names}), vydal {issuer} '
     'a platí do {not_after}. Stáhnete si ho na zápisových stránkách, v části Certifikáty.\n\n'
     '-- {site}')
_put('cert_portal_declined', 'en', 'Your request for {names} was declined',
     '{site}: your certificate request',
     'Hello {name}, your request for a certificate for <b>{names}</b> was declined: {reason}',
     'Ask your administrators if this is a mistake.', 'Sent by acme - {site}.',
     'Hello {name},\n\nyour request for a certificate for {names} was declined: {reason}\n\n'
     'Ask your administrators if this is a mistake.\n\n-- {site}')
_put('cert_portal_declined', 'cs', 'Vaše žádost o {names} byla zamítnuta',
     '{site}: vaše žádost o certifikát',
     'Dobrý den, {name}, vaše žádost o certifikát pro <b>{names}</b> byla zamítnuta: {reason}',
     'Pokud jde o omyl, obraťte se na své správce.', 'Poslal acme - {site}.',
     'Dobrý den, {name},\n\nvaše žádost o certifikát pro {names} byla zamítnuta: {reason}\n\n'
     'Pokud jde o omyl, obraťte se na své správce.\n\n-- {site}')

TONE = {'bad': ('#b91c1c', '#fef2f2'), 'warn': ('#b45309', '#fff7ed'),
        'ok': ('#15803d', '#f0fdf4')}
FACTS = {'en': [('cert', 'Certificate'), ('names', 'Names'), ('target', 'Target'),
                ('issuer', 'Issuer'), ('version', 'Version'), ('serial', 'Serial'),
                ('not_after', 'Valid until')],
         'cs': [('cert', 'Certifikát'), ('names', 'Jména'), ('target', 'Cíl'),
                ('issuer', 'Vydavatel'), ('version', 'Verze'), ('serial', 'Sériové číslo'),
                ('not_after', 'Platí do')]}


def messages():
    """The entries of TEXT_MESSAGES: each event a mail, and an SMS where it has one."""
    out = []
    for mid, title, says, ph, tone, sms in EVENTS:
        out.append({'id': mid, 'kind': 'mail', 'group': GROUP, 'title': 'Certificates: ' + title,
                    'short': title, 'says': says, 'fields': mail_fields(mid, ph),
                    'render': _renderer(mid), 'tone': tone})
        if sms:
            out.append({'id': mid + '_sms', 'kind': 'sms', 'group': GROUP,
                        'title': 'Certificates: ' + title + ' (SMS)', 'short': title,
                        'says': says, 'fields': sms_fields(mid, ph)})
    return out


def event(mid):
    return next((e for e in EVENTS if e[0] == mid), None)


class _Safe(dict):
    """Placeholders filled, one not given left as it is written."""
    def __missing__(self, k):
        return '{' + k + '}'


def fill(text, values, esc=False):
    v = {k: (_html.escape(str(x), quote=True) if esc else str(x))
         for k, x in (values or {}).items()}
    try:
        return string.Formatter().vformat(str(text or ''), (), _Safe(v))
    except (ValueError, IndexError):
        return str(text or '')


def mail_html(mid, w, values, lang):
    """The mail, drawn as the engine's own mails look: the band, the white card,
    the facts, the note."""
    ev = event(mid)
    band, light = TONE.get(ev[4] if ev else 'warn', TONE['warn'])
    p = 'c_' + _p(mid)
    h = lambda t: _html.escape(str(t), quote=True)          # noqa: E731
    font = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
    rows = []
    lede = fill(w.get(p + '_lede', ''), values, esc=True)
    if lede.strip():
        rows.append('<p style="margin:0 0 16px;font-size:15px;line-height:1.55;color:#111827">'
                    '%s</p>' % lede)
    facts = [(lab, values.get(k)) for k, lab in FACTS.get(lang, FACTS['en'])
             if k in (ev[3] if ev else ()) and values.get(k) not in (None, '')]
    if facts:
        rows.append('<table role="presentation" cellspacing="0" cellpadding="0" border="0" '
                    'style="margin:0 0 16px;font-size:13.5px;color:#374151;%s">%s</table>' % (
                        font, ''.join('<tr><td style="padding:2px 14px 2px 0;color:#6b7280;'
                                      'white-space:nowrap">%s</td><td style="padding:2px 0">'
                                      '%s</td></tr>' % (h(a), h(b)) for a, b in facts)))
    note = fill(w.get(p + '_note', ''), values, esc=True)
    if note.strip():
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0"><tr><td bgcolor="%s" style="padding:12px 16px;background:%s;'
                    'border-left:4px solid %s;font-size:13px;line-height:1.5;color:#1f2937;%s">'
                    '%s</td></tr></table>' % (light, light, band, font, note))
    title = h(fill(w.get(p + '_title', ''), values))
    foot = fill(w.get(p + '_foot', ''), values, esc=True)
    return ('<!doctype html><html lang="%s"><head><meta charset="utf-8"><title>%s</title></head>'
            '<body style="margin:0;padding:0;background:#f3f4f6;%s">'
            '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'bgcolor="#f3f4f6"><tr><td align="center" style="padding:24px 12px">'
            '<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" '
            'style="max-width:600px;width:100%%">'
            '<tr><td bgcolor="%s" style="background:%s;padding:16px 24px;border-radius:12px 12px '
            '0 0;color:#ffffff;font-size:17px;font-weight:600;%s">%s</td></tr>'
            '<tr><td bgcolor="#ffffff" style="background:#ffffff;padding:24px;border-radius:0 0 '
            '12px 12px">%s</td></tr>'
            '<tr><td style="padding:14px 8px;font-size:12px;line-height:1.5;color:#6b7280;'
            'text-align:center;%s">%s</td></tr>'
            '</table></td></tr></table></body></html>') % (
        lang, title, font, band, band, font, title, ''.join(rows), font, foot)


def draw_with(mid, w, values, lang):
    """One message drawn from the words `w` (texts_for) and the values."""
    if mid.endswith('_sms'):
        base = mid[:-4]
        return {'sms': fill(w.get('c_' + _p(base) + '_sms', ''), values)}
    p = 'c_' + _p(mid)
    return {'subject': fill(w.get(p + '_subject', ''), values),
            'html': mail_html(mid, w, values, lang),
            'text': fill(w.get(p + '_body', ''), values)}


def _renderer(mid):
    def render(w, smp, lang):
        return draw_with(mid, w, smp, lang)
    return render


def span(seconds, lang='en'):
    """How long, in words of the language: 9 days, 5 h, 20 min / 9 dní, 5 h, 20 min."""
    s = max(0, int(float(seconds or 0)))
    d, h, m = s // 86400, (s % 86400) // 3600, (s % 3600) // 60
    if d:
        if lang == 'cs':
            return '%d %s' % (d, 'den' if d == 1 else ('dny' if 2 <= d <= 4 else 'dní'))
        return '%d day%s' % (d, '' if d == 1 else 's')
    if h:
        return '%d h' % h
    return '%d min' % max(1, m)


def when(ts):
    if not ts:
        return '?'
    try:
        return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)
