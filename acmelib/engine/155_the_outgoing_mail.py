# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The outgoing mail (1.0.95)
# ---------------------------------------------------------------------------
# Every mail goes through here: tried at once, and what the receiving side
# did not take yet - greylisting's "try again later", a server away, a full
# mailbox - waits and is tried again, for mail_retry_hours (a code to sign
# in with only while it is good). Kept in the database both nodes share, as
# rows of their own under random keys (no numbers two nodes could both give
# out): a row says which node sends it, the other takes it over when that
# one is gone, and the pages of either node can send one again or take it
# away. What a mail holds - a QR code, a key, a code - is sealed while it
# waits and thrown away once it went.

MAILQ_PREFIX = 'mailq:'
MAILB_PREFIX = 'mailb:'
MAILQ_DELAYS = (60, 120, 300, 600, 900, 1800)           # then every hour
MAILQ_CODE_DELAYS = (30, 60)                            # then every minute
MAILQ_KIND_WORDS = {'token': 'a token (QR code)', 'code': 'a code to sign in',
                    'verify': 'a code to check an address', 'test': 'a test',
                    'alert': 'an alert', 'report': 'a report',
                    'other': 'a mail'}
MAILQ_STATES = ('sending', 'waiting', 'sent', 'failed', 'expired')
MAILQ_LOCK = threading.Lock()


def mailq_new_id():
    return '%013d-%s' % (int(time.time() * 1000), secrets.token_hex(4))


def mailq_read(store, qid):
    raw = store.get_meta(MAILQ_PREFIX + qid)
    if not raw:
        return None, None
    try:
        return json.loads(raw), raw
    except ValueError:
        return None, None


def mailq_cas(store, qid, raw, rec):
    """Written only over what was read: of two writers, one wins."""
    return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                             (json.dumps(rec), MAILQ_PREFIX + qid, raw)))


def mailq_body(store, qid):
    sealed = store.get_meta(MAILB_PREFIX + qid)
    if not sealed:
        return None
    raw = unseal_secret(sealed, 'mailq:' + qid)
    if not raw:
        return None
    try:
        import email
        import email.policy
        return email.message_from_bytes(base64.b64decode(raw), policy=email.policy.default)
    except Exception:                                   # noqa: BLE001
        return None


def mailq_body_drop(store, qid):
    store.db.run('DELETE FROM meta WHERE k = ?', (MAILB_PREFIX + qid,))


def mailq_delay(rec):
    n = int(rec.get('tries') or 1)
    row = MAILQ_CODE_DELAYS if rec.get('kind') in ('code', 'verify') else MAILQ_DELAYS
    last = 60 if row is MAILQ_CODE_DELAYS else 3600
    return row[n - 1] if 0 < n <= len(row) else last


def mailq_subject_kept(subject, kind):
    """The subject as the outgoing-mail list shows it. A code's mail has the
    code in its subject - kept as dots there (1.0.101): every role, the
    read-only one too, saw the codes people were signing in with. The mail
    itself, sealed, still has it."""
    said = str(subject or '')[:300]
    if kind in ('code', 'verify'):
        said = re.sub(r'\d{4,10}', '••••••', said)
    return said


def mail_deliver(store, msg, to, kind='other', name='', by='', purpose='', expires=None):
    """A mail sent now, and kept for another try when it was not taken.
    Returns the steps; raises MailError (with .queued = the state it is left
    in: waiting, failed) when it did not go now."""
    if (CONFIG.get('mail_mode') or 'off') == 'off':
        raise MailError('sending mail is switched off - Settings → Mail', [])
    to = [str(x) for x in (to or [])]
    qid = mailq_new_id()
    now = time.time()
    rec = {'qid': qid, 'created': now, 'node': node_name(), 'kind': kind,
           'purpose': str(purpose or ''), 'name': str(name or ''), 'by': str(by or ''),
           'to': to, 'subject': mailq_subject_kept(msg.get('Subject'), kind),
           'size': 0, 'state': 'sending', 'tries': 0, 'last_try': now, 'next_at': 0,
           'expires': float(expires) if expires else
           now + 3600 * int(CONFIG.get('mail_retry_hours') or 24),
           'history': [], 'said': '', 'steps': []}
    data = msg.as_bytes()
    rec['size'] = len(data)
    store.set_meta(MAILB_PREFIX + qid, seal_secret(base64.b64encode(data).decode('ascii'),
                                                   'mailq:' + qid))
    store.set_meta(MAILQ_PREFIX + qid, json.dumps(rec))
    return mailq_attempt(store, qid, msg=msg, raise_err=True, claimed=True)


def mailq_attempt(store, qid, msg=None, raise_err=False, claimed=False):
    rec, raw = mailq_read(store, qid)
    if not rec:
        return None
    now = time.time()
    if not claimed:
        if rec.get('state') not in ('waiting',):
            return None
        rec.update(state='sending', last_try=now, node=node_name())
        if not mailq_cas(store, qid, raw, rec):
            return None                 # taken by another meanwhile
        raw = json.dumps(rec)
    if msg is None:
        msg = mailq_body(store, qid)
    if msg is None:
        rec.update(state='expired', said='what the mail held is gone - it cannot be sent')
        store.set_meta(MAILQ_PREFIX + qid, json.dumps(rec))
        return None
    err = None
    try:
        steps = mail_send(store, msg, rec.get('to') or [])
    except MailError as e:
        err, steps = e, e.steps
        if e.left is not None and e.left and len(e.left) < len(rec.get('to') or []):
            rec['done_to'] = sorted(set(rec.get('done_to') or []) |
                                    (set(rec.get('to') or []) - set(e.left)))
            rec['to'] = list(e.left)            # the rest took it (1.0.206)
    except Exception as e:                              # noqa: BLE001
        err, steps = MailError(str(e) or e.__class__.__name__, []), []
    rec['tries'] = int(rec.get('tries') or 0) + 1
    rec['last_try'] = now
    rec['steps'] = steps[-12:]
    rec['history'] = (rec.get('history') or [])[-19:] + [{
        'at': now, 'node': node_name(), 'ok': err is None,
        'said': (str(err) if err else (([s for s in steps if s.get('ok')] or [{}])[-1]
                                       .get('said') or 'sent'))[:400]}]
    who = ', '.join(rec.get('to') or [])
    if err is None:
        rec.update(state='sent', sent_at=now, said=rec['history'][-1]['said'], next_at=0)
        store.set_meta(MAILQ_PREFIX + qid, json.dumps(rec))
        mailq_body_drop(store, qid)
        if rec['tries'] > 1:
            store.add_event('mail', 'the mail to %s (%s) went on try %d' % (
                who, MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail'), rec['tries']))
        return steps
    rec['said'] = str(err)[:400]
    if err.permanent:
        rec['state'] = 'failed'
        store.add_event('mail', 'the mail to %s (%s) was refused for good: %s' % (
            who, MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail'), str(err)[:300]), 'bad')
    elif now >= float(rec.get('expires') or 0):
        rec['state'] = 'expired'
        store.add_event('mail', 'the mail to %s (%s) was given up after %d tries: %s' % (
            who, MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail'), rec['tries'],
            str(err)[:300]), 'bad')
    else:
        rec['state'] = 'waiting'
        rec['next_at'] = min(now + mailq_delay(rec), float(rec.get('expires') or now))
        if rec['tries'] == 1:
            store.add_event('mail', 'the mail to %s (%s) did not go yet - tried again from '
                            'the outgoing mail: %s' % (
                                who, MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail'),
                                str(err)[:300]), 'warn')
    store.set_meta(MAILQ_PREFIX + qid, json.dumps(rec))
    if rec['state'] in ('expired',):
        mailq_body_drop(store, qid)
    err.queued = rec['state']
    err.next_at = rec.get('next_at')
    err.qid = qid
    if raise_err:
        raise err
    return None


def mailq_all(store, open_only=False):
    """Every mail remembered - or, `open_only`, those still to do something
    with (1.0.101): every 10 s every node read each mail of the last two
    weeks, steps and all, to find the few still waiting."""
    out = []
    sql = "SELECT k, v FROM meta WHERE k LIKE 'mailq:%'"
    if open_only:
        sql += (" AND (v LIKE '%\"state\": \"waiting\"%' OR v LIKE '%\"state\": \"sending\"%'"
                " OR v LIKE '%\"state\": \"failed\"%')")
    for r in store.db.rows(sql):
        try:
            rec = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        rec['qid'] = r['k'][len(MAILQ_PREFIX):]
        out.append(rec)
    out.sort(key=lambda x: -float(x.get('created') or 0))
    return out


MAILQ_FULL_AT = [0.0]


def mailq_tick(store):
    """What the outgoing mail does every few seconds on every node."""
    if not MAILQ_LOCK.acquire(False):
        return
    try:
        now = time.time()
        me = node_name()
        ha = bool(CONFIG.get('ha_mode'))
        alive = set()
        if ha:
            try:
                alive = {n['name'] for n in ha_nodes(store) if n.get('alive')}
            except Exception:                           # noqa: BLE001
                alive = {me}
        keep_s = 86400 * int(CONFIG.get('mail_keep_days') or 14)
        sent_now = 0
        paused = (CONFIG.get('mail_mode') or 'off') == 'off'
        # All of them - to forget the old ones - every ten minutes; the open
        # ones every time.
        full = now - MAILQ_FULL_AT[0] > 600
        if full:
            MAILQ_FULL_AT[0] = now
        for rec in mailq_all(store, open_only=not full):
            qid = rec['qid']
            state = rec.get('state')
            mine = rec.get('node') == me or not ha
            if state in ('sent', 'failed', 'expired') and \
                    now - float(rec.get('sent_at') or rec.get('last_try') or
                                rec.get('created') or 0) > keep_s:
                store.db.run('DELETE FROM meta WHERE k IN (?, ?)',
                             (MAILQ_PREFIX + qid, MAILB_PREFIX + qid))
                continue
            if state == 'failed' and now > float(rec.get('expires') or 0):
                # Refused for good stays "refused for good" (1.0.103), not
                # "given up": what it held goes, the reason stays.
                if store.get_meta(MAILB_PREFIX + qid):
                    mailq_body_drop(store, qid)
                continue
            if paused and rec.get('kind') not in ('code', 'verify'):
                continue        # kept as it is until mail is switched on again
            # A while past its time (1.0.206): the last try is due at the very time
            # it runs out, and was given up here before it was made - with no word.
            if state in ('waiting', 'sending') and \
                    now > float(rec.get('expires') or 0) + (120 if state != 'sending' else 600):
                _, raw = mailq_read(store, qid)
                if raw:
                    rec.pop('qid', None)
                    rec.update(state='expired', next_at=0, said=rec.get('said') or 'not sent in time')
                    if mailq_cas(store, qid, raw, rec):
                        mailq_body_drop(store, qid)
                        store.add_event('mail', 'the mail to %s (%s) was given up after %d tries: %s'
                                        % (', '.join(rec.get('to') or []),
                                           MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail'),
                                           int(rec.get('tries') or 0), str(rec.get('said'))[:300]),
                                        'bad')
                continue
            if paused:
                # Mail switched off (1.0.103): nothing tried while it is, as
                # the page says - and nothing but a code past its time given
                # up for it either.
                continue
            if state == 'sending' and now - float(rec.get('last_try') or 0) > 600 and \
                    (mine or rec.get('node') not in alive):
                # Left half way by a node that stopped: tried again.
                _, raw = mailq_read(store, qid)
                if raw:
                    rec.pop('qid', None)
                    rec.update(state='waiting', next_at=now, node=me)
                    mailq_cas(store, qid, raw, rec)
                continue
            if state != 'waiting':
                continue
            if not mine:
                # The node it waits on is gone (5 min): this one sends it.
                if rec.get('node') in alive or now - float(rec.get('last_try') or 0) < 300:
                    continue
            if float(rec.get('next_at') or 0) > now or sent_now >= 25:
                continue
            sent_now += 1
            try:
                mailq_attempt(store, qid)
            except Exception as e:                      # noqa: BLE001
                log('the outgoing mail %s: %s' % (qid, e), 'warn')
    finally:
        MAILQ_LOCK.release()


def mailq_counts(store):
    c = collections.Counter()
    for r in store.db.rows("SELECT v FROM meta WHERE k LIKE 'mailq:%'"):
        m = re.search(r'"state": "([a-z]+)"', r['v'] or '')
        if m:
            c[m.group(1)] += 1
    return {k: int(c.get(k, 0)) for k in MAILQ_STATES}


def mailq_view(rec):
    """A row as the pages see it: no body, never."""
    out = {k: rec.get(k) for k in ('qid', 'created', 'node', 'kind', 'purpose', 'name', 'by',
                                    'to', 'subject', 'size', 'state', 'tries', 'last_try',
                                    'next_at', 'expires', 'sent_at', 'said')}
    out['kind_words'] = MAILQ_KIND_WORDS.get(rec.get('kind'), 'a mail')
    # Kept by an earlier version with the code in it (1.0.101).
    out['subject'] = mailq_subject_kept(out.get('subject'), rec.get('kind'))
    return out


MAILQ_RETRY_WHY = {}


def mailq_retry(store, qids, by=''):
    """Tried again now, on this node - whichever node it waited on."""
    done, skipped = [], []
    MAILQ_RETRY_WHY.clear()
    for qid in qids:
        rec, raw = mailq_read(store, qid)
        if not rec or rec.get('state') not in ('waiting', 'failed'):
            skipped.append(qid)
            continue
        if not store.get_meta(MAILB_PREFIX + qid):
            skipped.append(qid)
            continue
        if time.time() > float(rec.get('expires') or 0):
            # Asked by hand: given the time of a new mail again - a code to
            # sign in with is not, it is no good any more.
            if rec.get('kind') in ('code', 'verify'):
                skipped.append(qid)
                MAILQ_RETRY_WHY['code'] = MAILQ_RETRY_WHY.get('code', 0) + 1
                continue
            rec['expires'] = time.time() + 3600 * int(CONFIG.get('mail_retry_hours') or 24)
        rec.update(state='waiting', next_at=0, node=node_name())
        if mailq_cas(store, qid, raw, rec):
            done.append(qid)
        else:
            skipped.append(qid)
    if done:
        store.add_event('mail', '%s asked for %d mail(s) of the outgoing mail to be sent again '
                        'now' % (by or 'somebody', len(done)), who=by or None)
        threading.Thread(target=lambda: [mailq_attempt(store, q) for q in done],
                         name='mail-again', daemon=True).start()
    return done, skipped


def mailq_drop(store, qids, by=''):
    n = 0
    for qid in qids:
        n += int(store.db.run('DELETE FROM meta WHERE k = ?', (MAILQ_PREFIX + qid,)) or 0)
        store.db.run('DELETE FROM meta WHERE k = ?', (MAILB_PREFIX + qid,))
    if n:
        store.add_event('mail', '%s took %d mail(s) out of the outgoing mail' % (
            by or 'somebody', n), 'warn', who=by or None)
    return n


def mail_sender():
    """The address mail goes out from (1.0.206): "Name <addr>" saved before it
    was refused is taken as its address - the server refused the header."""
    from email.utils import parseaddr as _pa
    got = str(CONFIG.get('mail_from') or '').strip()
    return (_pa(got)[1] or got) if got else ''

