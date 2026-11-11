# -*- coding: utf-8 -*-
"""A report of the tests run (1.0.73): the certificates' window → Run the tests…, with Send a
report - by mail to the addresses given (the report's, or the alerts' by default) and, with SMS
on, one line to the numbers given. Built from what each test said last (cert_checks), grouped
by certificate, in the frame of acme's other mails (engine: _al_page, _al_msg, alert_send).
"""
from __future__ import annotations

import html
import re
import time

from acmelib import engine as E
from acmelib.certs import checks as C

STATE_WORDS = {
    'ok': ('serves it', 'servíruje ho', 'good'), 'warn': ('serves it - but', 'servíruje ho - ale', 'warn'),
    'old': ('an old version', 'starou verzi', 'bad'), 'other': ('another certificate', 'jiný certifikát', 'bad'),
    'answer': ('wrong answer', 'špatná odpověď', 'bad'), 'unreachable': ('not reached', 'nedostupné', 'bad'),
    '': ('not run', 'nespuštěno', 'info')}
MAIL_RE = re.compile(r'^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+\Z')
PHONE_RE = re.compile(r'^\+?[0-9 ]{6,20}\Z')


def addresses(v):
    got = [a for a in re.split(r'[\s,;]+', str(v or '')) if a] if not isinstance(v, list) else \
        [str(a).strip() for a in v if str(a).strip()]
    for a in got:
        if not MAIL_RE.match(a):
            raise ValueError('%s is not a mail address' % a)
    return got[:20]


def phones(v):
    got = [a for a in re.split(r'[,;\n]+', str(v or '')) if a.strip()] if not isinstance(v, list) else \
        [str(a) for a in v if str(a).strip()]
    got = [re.sub(r'\s+', '', a) for a in got]
    for a in got:
        if not PHONE_RE.match(a):
            raise ValueError('%s is not a phone number' % a)
    return got[:10]


def _rows(store, ids):
    out = []
    for i in ids:
        r = store.db.row('SELECT * FROM cert_checks WHERE id = ?', (int(i),))
        if r:
            out.append(C.row_public(store, r))
    return out


def counts(rows):
    good = sum(1 for r in rows if (r.get('last_state') or '') == 'ok')
    warn = sum(1 for r in rows if (r.get('last_state') or '') == 'warn')
    return good, warn, len(rows) - good - warn


def build(store, ids, what, lang=None):
    """-> (subject, html page, text) of the results of these tests."""
    lang = lang or E.report_lang()
    al = lambda cs, en: E._al(lang, cs, en)  # noqa: E731
    h = E._h
    rows = _rows(store, ids)
    good, warn, bad = counts(rows)
    site = str(E.CONFIG.get('site_name') or E.socket.gethostname())
    level = 'bad' if bad else ('warn' if warn else 'good')
    title = al('Výsledky testů', 'The results of the tests')
    summary = al('%d v pořádku, %d s varováním, %d selhalo', '%d fine, %d with a warning, %d failed') % (
        good, warn, bad)
    if lang == 'cs':
        what = re.sub(r'^the tests of (.+)$', r'testy certifikátu \1', what)
        what = re.sub(r'^the test (.+) on its certificates$', r'test \1 na jeho certifikátech', what)
        what = 'všechny testy' if what == 'every test' else what
    body = [E._al_card(level, summary, [h(what), h(E._al_when(time.time()))])]
    text = ['%s - %s' % (title, site), what, summary, '']
    by_cert = {}
    for r in rows:
        by_cert.setdefault(r.get('cert') or '?', []).append(r)
    th = ('<th align="left" style="padding:6px 8px;font-size:11px;color:#6b7280;text-transform:uppercase;'
          'letter-spacing:.5px;border-bottom:1px solid #e5e7eb">%s</th>')
    td = '<td style="padding:7px 8px;font-size:13px;color:#374151;border-bottom:1px solid #f3f4f6;vertical-align:top">%s</td>'
    for cert in sorted(by_cert):
        body.append(E._al_h(cert))
        text.append(cert.upper())
        tr = [''.join(th % al(*x) for x in (('Test', 'Test'), ('Kde', 'Where'), ('Stav', 'State'),
                                            ('Co řekl', 'What it said'), ('Kdy', 'When')))]
        for r in by_cert[cert]:
            st = r.get('last_state') or ''
            w = STATE_WORDS.get(st, (st, st, 'info'))
            edge, back, ink = E.AL_COLORS[w[2]]
            badge = ('<span style="display:inline-block;padding:2px 8px;border-radius:9px;font-size:11.5px;'
                     'font-weight:700;background:%s;color:%s;white-space:nowrap">%s</span>'
                     % (back, ink, h(al(w[1], w[0]))))
            said = E.detail_redact(r.get('last_said') or '')
            tr.append(''.join(td % x for x in (h(r.get('test') or ''), h(r.get('where') or ''), badge,
                                               h(said[:400]), h(E._al_when(r.get('last_at'))))))
            text.append('- %s (%s): %s - %s' % (r.get('test'), r.get('where'), al(w[1], w[0]), said[:300]))
        body.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">'
                    '%s</table>' % ''.join('<tr>%s</tr>' % x for x in tr))
        text.append('')
    foot = h(al('Poslal %s z %s, %s.', 'Sent by %s from %s, %s.') % (
        E.node_name(), site, E._al_when(time.time())))
    page = E._al_page(lang, title, 'acme · ' + site, E.AL_COLORS[level][0], ''.join(body), foot)
    subject = '[acme] %s: %s - %s' % (title, summary, site)
    text += ['-- ', html.unescape(foot)]
    return subject, page, '\n'.join(text)


def sms_line(store, ids, lang=None):
    lang = lang or E.report_lang()
    rows = _rows(store, ids)
    good, warn, bad = counts(rows)
    failing = ', '.join('%s/%s' % (r.get('cert'), r.get('test')) for r in rows
                        if (r.get('last_state') or '') not in ('ok', 'warn'))[:200]
    return E._al(lang, 'acme testy: %d OK, %d varování, %d chyb%s', 'acme tests: %d fine, %d warnings, '
                 '%d failed%s') % (good, warn, bad, (' - ' + failing) if failing else '')


def send(store, ids, what, to, sms_to, by, step=None):
    """The report of these tests sent; -> words of how it went (said in the job)."""
    said = []
    if to:
        try:
            subject, page, text = build(store, ids, what)
            entry = E.alert_send(store, E._al_msg(subject, page, text, to), to, 'report', [])
        except Exception as e:                          # noqa: BLE001 - no sender, no mail set up
            entry = {'ok': False, 'said': str(e)}
        said.append(('the report went to %s' % ', '.join(to)) if entry.get('ok')
                    else 'the report did not go: %s' % entry.get('said'))
        if step:
            step(said[-1], 'ok' if entry.get('ok') else 'warn')
    for n in sms_to or []:
        try:
            E.sms_send(n, sms_line(store, ids))
            said.append('the SMS went to %s' % n)
            if step:
                step(said[-1], 'ok')
        except Exception as e:                          # noqa: BLE001
            said.append('the SMS to %s did not go: %s' % (n, e))
            if step:
                step(said[-1], 'warn')
    store.add_event('certificates', '%s: the report of %s - %s' % (by, what, '; '.join(said) or 'nothing'),
                    'info', who=by)
    return '; '.join(said)
