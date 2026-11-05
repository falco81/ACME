# -*- coding: utf-8 -*-
"""
Telling people what happened to the certificates - by mail to
certs_notify_mail and by SMS to certs_notify_sms - in the words of Settings →
Message texts (texts.py), in the language of the alerts (alerts_lang, else
mail_lang).

    send(store, mid, key, values, force=False)
        one notification: mid is a message of texts.py (cert_renew_failed ...),
        key what it is about - each key at most every 6 hours
    notify(store, key, subject, words, force=False)
        the renewer's own call (renewer.notify), its key read for what it is
        about: renew:<id> expired:<id> expiring:<id> deploy:<id> - the words
        then those of the texts, the values from the certificate
    cert_values(store, cert, **more)
        the placeholders of one certificate

Never raises: a notification that cannot go is a line in the log.
"""
from __future__ import annotations

import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import texts as T

NOTIFY_EVERY = 6 * 3600
KEY_MID = {'renew': 'cert_renew_failed', 'expired': 'cert_expired',
           'expiring': 'cert_expiring', 'deploy': 'cert_deploy_failed'}


def lang():
    got = str(E.CONFIG.get('alerts_lang') or E.CONFIG.get('mail_lang') or 'cs')
    return got if got in ('cs', 'en') else 'cs'


def _split(v):
    return [w for w in str(v or '').replace(';', ',').replace(' ', ',').split(',') if w]


def recipients(store, cert):
    """certs_notify_mail and the mail of the certificate's owner team (teams.py), each once."""
    out = []
    extra = []
    try:
        from acmelib.certs import teams
        extra = teams.contact_mails(store, cert)
    except Exception as e:                              # noqa: BLE001
        E.log('the owner of %s could not be read: %s' % ((cert or {}).get('name'), e), 'warn')
    for w in _split(E.CONFIG.get('certs_notify_mail')) + extra:
        if w.lower() not in {x.lower() for x in out}:
            out.append(w)
    return out


def cert_values(store, cert, **more):
    """The placeholders of a certificate (a row of certs, or its id or name)."""
    if not isinstance(cert, dict):
        cert = S.cert_get(store, cert) or {}
    na = cert.get('not_after')
    lng = lang()
    left = ''
    if na:
        left = T.span(max(0.0, float(na) - time.time()), lng)
    out = {'cert': cert.get('name') or '?',
           'names': ', '.join(S.jload(cert.get('names'), []) or []) if not isinstance(
               cert.get('names'), list) else ', '.join(cert['names']),
           'not_after': T.when(na), 'left': left or '?', 'issuer': cert.get('issuer') or '-',
           'serial': cert.get('serial') or '-', 'version': cert.get('version') or 0,
           'error': (cert.get('last_error') or '')[:500], 'retry': '-', 'target': '-',
           'node': E.node_name(), 'site': str(E.CONFIG.get('site_name') or E.node_name()),
           'reason': '', 'name': cert.get('owner') or ''}
    if cert.get('next_try'):
        out['retry'] = T.span(max(0.0, float(cert['next_try']) - time.time()), lng)
    for k, v in more.items():
        if v is not None:
            out[k] = v
    return out


def _mail(to, drawn):
    site = str(E.CONFIG.get('site_name') or E.node_name())
    sender = E.mail_sender() or 'acme@%s' % E.node_name()
    msg = EmailMessage()
    # one line (1.0.51): a CA's error of several lines in {error} made the message fail -
    # and the alert was lost for six hours
    subj = ' '.join(str(drawn.get('subject') or site).split())[:300]
    msg['Subject'] = '[acme %s] %s' % (E.node_name(), subj)
    msg['From'] = formataddr((str(E.CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = ', '.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(str(drawn.get('text') or ''))
    if drawn.get('html'):
        msg.add_alternative(str(drawn['html']), subtype='html')
    return msg


def drawn(mid, values, lng=None):
    """(mail, sms) of one message with these values, in the words saved now."""
    lng = lng or lang()
    w = E.texts_for(T.GROUP, lng)
    mail = T.draw_with(mid, w, values, lng)
    sms = T.draw_with(mid + '_sms', w, values, lng) if T.event(mid) and T.event(mid)[5] else None
    return mail, sms


def send(store, mid, key, values, force=False, mail_to=None, sms_to=None):
    """One notification (see the top). Returns what went: {'mail': [...], 'sms': [...]}."""
    went = {'mail': [], 'sms': []}
    try:
        mk = 'certs:notified:%s' % key
        if key and not force:
            last = float(store.get_meta(mk) or 0)
            if time.time() - last < NOTIFY_EVERY:
                return went
        mail, sms = drawn(mid, values)
        if key:
            store.set_meta(mk, str(time.time()))     # once it is drawn (1.0.51)
        to = list(mail_to) if mail_to is not None else _split(E.CONFIG.get('certs_notify_mail'))
        if to:
            try:
                E.mail_deliver(store, _mail(to, mail), to, kind='certs', purpose='certificates')
                went['mail'] = to
            except Exception as e:                      # noqa: BLE001
                E.log('the mail "%s" could not go: %s' % (mail.get('subject'), e), 'warn')
        tels = list(sms_to) if sms_to is not None else _split(E.CONFIG.get('certs_notify_sms'))
        if sms and tels:
            text = E.sms_plain(sms['sms'])[:480]
            for tel in tels:
                try:
                    E.sms_send(tel, text)
                    went['sms'].append(tel)
                except Exception as e:                  # noqa: BLE001
                    E.log('the SMS "%s" could not go to %s: %s' % (text[:60], tel, e), 'warn')
    except Exception as e:                              # noqa: BLE001
        E.log('telling about %s (%s): %s' % (key, mid, e), 'warn')
    return went


def notify(store, key, subject, words, force=False):
    """renewer.notify, in the words of the texts: the key says what it is about."""
    try:
        what, _, ident = str(key or '').partition(':')
        mid = KEY_MID.get(what)
        cert = S.cert_get(store, int(ident)) if ident.isdigit() else None
        if not mid or not cert:
            return send_plain(store, key, subject, words, force,
                              mail_to=recipients(store, cert) if cert else None)
        more = {}
        if what in ('renew', 'deploy'):
            more['error'] = str(words or '')[:500]
        if what == 'deploy':
            # Said once per deployment by the deployer already (deploy-one:<id>):
            # the renewer's summary of the same is not sent again.
            if time.time() - float(store.get_meta('certs:notified:deploycert:%s' % cert['id'])
                                   or 0) < 120:
                return {'mail': [], 'sms': []}
            more['target'] = ', '.join(sorted({d['target'] for d in store.db.rows(
                "SELECT target FROM cert_deploys WHERE cert_id = ? AND state = 'failed'",
                (cert['id'],))})) or '-'
        return send(store, mid, key, cert_values(store, cert, **more), force,
                    mail_to=recipients(store, cert))
    except Exception as e:                              # noqa: BLE001
        E.log('telling about %s: %s' % (subject, e), 'warn')
        return {'mail': [], 'sms': []}


notify._texts = True


def send_plain(store, key, subject, words, force=False, mail_to=None):
    """What is not one of the texts' events: the subject and the words as they are."""
    went = {'mail': [], 'sms': []}
    try:
        mk = 'certs:notified:%s' % key
        if not force and time.time() - float(store.get_meta(mk) or 0) < NOTIFY_EVERY:
            return went
        store.set_meta(mk, str(time.time()))
        to = list(mail_to) if mail_to is not None else _split(E.CONFIG.get('certs_notify_mail'))
        # each way on its own (1.0.52): a mail that failed stopped the SMS too
        if to:
            try:
                E.mail_deliver(store, _mail(to, {'subject': subject, 'text': '%s\n\n%s\n\n-- acme '
                                                                             'on %s\n' % (
                    subject, words, E.node_name())}), to, kind='certs', purpose='certificates')
                went['mail'] = to
            except Exception as e:                      # noqa: BLE001
                E.log('mailing about %s: %s' % (subject, e), 'warn')
        for tel in _split(E.CONFIG.get('certs_notify_sms')):
            try:
                E.sms_send(tel, E.sms_plain('acme: %s - %s' % (subject, words))[:300])
                went['sms'].append(tel)
            except Exception as e:                      # noqa: BLE001
                E.log('an SMS about %s: %s' % (subject, e), 'warn')
    except Exception as e:                              # noqa: BLE001
        E.log('telling about %s: %s' % (subject, e), 'warn')
    return went


def install(renewer_mod):
    """The renewer's notify() made to speak in the texts - unless it does already."""
    cur = getattr(renewer_mod, 'notify', None)
    if cur is None or getattr(cur, '_texts', False) or getattr(renewer_mod, 'NOTIFY_TEXTS', None):
        return False
    renewer_mod.notify = notify
    return True


def ok_wanted():
    return bool(int(E.CONFIG.get('certs_notify_ok') or 0))
