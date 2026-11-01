# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Deciding: one Access-Request, step by step
# ---------------------------------------------------------------------------
# The order (1.0.33): the realm and whether this client may use it, the
# directory - is the account there, in use, in a group that lets in - and
# its password, and the code last. Somebody who does not know the password
# can then neither guess codes nor lock a token out by guessing them, and a
# code is only used up by a request that would otherwise be let in. (Until
# 1.0.32 the code came first, as the old token server had it.)
#
# Every step is written down - what was asked, what came back, how long it
# took - and kept with the request, so that "why was I refused" is answered
# by opening one row rather than by reading a debug log.

class Decision(object):
    def __init__(self):
        self.steps = []
        self.began = time.time()
        self.result = 'reject'
        self.reason = ''
        self.acme = ''
        self.reply = []                 # [(Name, value)]
        self.realm = ''
        self.user = ''
        self.token_name = ''
        self.display = ''
        self.state = None               # an Access-Challenge's State (1.0.76)
        self.message = ''               # and the words of its second window

    def step(self, what, ok, said='', since=None):
        one = {'what': what, 'ok': ok, 'said': str(said or '')[:600]}
        if since is not None:
            one['ms'] = int((time.time() - since) * 1000)
        self.steps.append(one)
        if debugging('radius'):
            log('radius %s: %s%s' % (self.user or '?', what,
                                     (' - ' + str(said)) if said else ''), 'debug')
        return one

    def refuse(self, reason):
        self.result = 'reject'
        self.reason = reason
        return self


def client_realm_list(client):
    """The realms a client may use, by name, lower case; [] for any."""
    raw = (client or {}).get('realms') or ''
    if isinstance(raw, (list, tuple)):
        got = raw
    else:
        got = re.split(r'[,;\n]+', str(raw))
    return [str(x).strip().lower() for x in got if str(x).strip()]


def ipv6_usable():
    """Can a socket listen on :: here (the kernel's IPv6 on)?"""
    try:
        t = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        t.bind(('::', 0))
        return True
    except OSError:
        return False
    finally:
        t.close()


def realm_main_name(user, realm):
    """novak@dpmo.local as novak@dpmo.cz, where dpmo.local is another suffix
    of the realm whose own is dpmo.cz (1.0.117). Anything else as it is."""
    who, at, where = str(user or '').rpartition('@')
    if at and realm and where.lower() in (realm.get('aliases') or []) and \
            realm.get('suffix') not in (None, '', '*'):
        return '%s@%s' % (who, realm['suffix'])
    return str(user or '')


def realm_names(user, realm):
    """The name as written, then under each suffix of its realm (1.0.117)."""
    out = [str(user or '')]
    who, at, _where = out[0].rpartition('@')
    if at and realm and realm.get('suffix') not in (None, '', '*'):
        for suf in [realm['suffix']] + list(realm.get('aliases') or []):
            n = '%s@%s' % (who, suf)
            if n.lower() not in [x.lower() for x in out]:
                out.append(n)
    return out


class Authenticator(object):
    """What the RADIUS server asks: may this person in, and with what."""

    def __init__(self, store, tokens, dirs):
        self.store = store
        self.tokens = tokens
        self.dirs = dirs                 # name -> Directory

    def directory(self, name):
        return self.dirs.get(str(name or '').lower())

    @staticmethod
    def full_name(user, client_realm):
        """The name as it will be looked up: DOMAIN\\name as name, and the
        client's own realm added to a name that has none - what FreeRADIUS's
        hints file did, NAS by NAS. A dot at the end of the realm is dropped
        (corp.cz. is corp.cz) and a name with nothing before its @ is no
        name at all (1.0.33)."""
        said = str(user or '').strip()
        if said.count('@') > 1:
            # novak@foo@x.cz (1.0.101): the realm by the last @, the account
            # by the first - and a token under the rest, a second one for the
            # same person. Not a name.
            return ''
        if '\\' in said and '@' in said:
            # DOMAIN\\name@realm (1.0.101): the directory finds name, the
            # token is looked for under the whole of it - a second token for
            # the same person, made by whoever has the password before its
            # owner enrols. Not a name.
            return ''
        if '\\' in said:
            said = said.split('\\', 1)[1]
        if '@' in said:
            who, _, where = said.rpartition('@')
            where = where.strip().rstrip('.')
            who = who.strip()
            if not who or not where:
                return ''
            return '%s@%s' % (who, where)
        if not said:
            return ''
        if client_realm:
            said = '%s@%s' % (said, str(client_realm).strip().lstrip('@').rstrip('.'))
        return said

    @staticmethod
    def token_name(user, realm):
        if realm and realm.get('token_name') == 'bare':
            # Before the last @, as the realm is found by it (1.0.101).
            return norm_name(user.rpartition('@')[0] or user)
        # Under the realm's own suffix (1.0.117): novak@dpmo.local is
        # novak@dpmo.cz where dpmo.local is another suffix of the realm.
        return norm_name(realm_main_name(user, realm))

    @classmethod
    def token_for(cls, store, user, realm):
        """(the token's name, how it was found). Its own name first; then
        the name as written, for a token made before the suffix became
        another of the realm's (1.0.117); then the same account's token in
        another realm reading the same directory by the account name - the
        one the enrolment pages found and kept (portal_same_person)."""
        mine = cls.token_name(user, realm)
        if store.token(mine) or not realm:
            return mine, ''
        typed = norm_name(user)
        if typed != mine and store.token(typed):
            return typed, 'made before @%s was another suffix of the realm %s' % (
                typed.rpartition('@')[2], realm['name'])
        if realm.get('lookup') == 'sam' and realm.get('directory') and '@' in str(user):
            who = str(user).rpartition('@')[0]
            here = str(realm.get('directory') or '').lower()
            for r in store.realms():
                if not r.get('enabled') or r['id'] == realm['id'] or \
                        str(r.get('directory') or '').lower() != here or \
                        r.get('lookup') != 'sam' or r.get('suffix') in (None, '', '*'):
                    continue
                cand = cls.token_name('%s@%s' % (who, r['suffix']), r)
                if store.token(cand):
                    return cand, 'the same account (%s) in the realm %s, on the same directory' % (
                        who, r['name'])
        return mine, ''

    @staticmethod
    def find_person(ad, user, lookup, realm):
        """The directory entry; by userPrincipalName also under the realm's
        other suffixes (1.0.117): novak@dpmo.local whose UPN is
        novak@dpmo.cz."""
        entry = ad.find_user(user, lookup)
        if entry or lookup != 'upn':
            return entry
        for alt in realm_names(user, realm)[1:]:
            entry = ad.find_user(alt, 'upn')
            if entry:
                return entry
        return None

    def decide(self, user, password, client_realm='', src='', rid='', chap=False,
               how='radius', client=None):
        d = Decision()
        d.user = self.full_name(user, client_realm or CONFIG.get('default_realm') or '')
        if not d.user:
            d.step('a name', False, 'the request carries no User-Name, or only a realm')
            return d.refuse('the request carries no User-Name')
        bad = name_letters_problem(d.user)
        if bad:
            # Letters of another language, switched off (1.0.154): refused
            # before anything is asked - no directory, no token.
            d.step('a name', False, bad)
            return d.refuse('the name has letters this server does not take')
        if d.user != str(user):
            d.step('the name is read as %s' % d.user, True,
                   'the client adds @%s to a name without a realm' % client_realm
                   if client_realm and '@' not in str(user) else '')
        realm = self.store.realm_for(d.user)
        if not realm:
            d.step('a realm for %s' % d.user, False, 'no realm takes this name')
            return d.refuse('no realm takes the name %s' % d.user)
        d.realm = realm['name']
        d.step('the realm is %s' % realm['name'], True, {
            'acme': 'the password is the code from the phone',
            'password_acme': 'the password is the directory password followed by the code',
            'password': 'the password is the directory password alone',
            'challenge': 'the directory password, then the code in a second window'}[
                realm['auth_mode']])
        # Whether this client may use that realm at all (1.0.33): without it
        # the name typed chose the realm, and with it how strictly the
        # person is checked - user@wifi through the VPN, password alone.
        allowed = client_realm_list(client)
        if allowed and realm['name'].lower() not in allowed:
            d.step('the client may use the realm %s' % realm['name'], False,
                   'the client %s may use only: %s' % ((client or {}).get('name') or '?',
                                                       ', '.join(allowed)))
            return d.refuse('the client %s may not use the realm %s'
                            % ((client or {}).get('name') or '?', realm['name']))
        if chap or password is None:
            d.step('a password', False, 'CHAP or no User-Password: a one-time code can only '
                   'travel as PAP')
            return d.refuse('the request carries no User-Password (PAP)')
        if password and any(ord(c) < 32 or c == '\ufffd' for c in password):
            d.step('the password reads as text', False, 'what came is not text - is the shared '
                   'secret the same on both sides?')
            return d.refuse('the password does not decode: the shared secret is probably '
                            'not the same as on the client')
        if not password:
            d.step('a password', False, 'it is empty')
            return d.refuse('the password is empty')
        d.token_name, found_how = self.token_for(self.store, d.user, realm)
        if d.token_name != norm_name(d.user):
            d.step('the token is %s' % d.token_name, True, found_how or (
                'the realm keeps its tokens under @%s' % realm.get('suffix')
                if realm.get('token_name') != 'bare' else 'the realm keeps its tokens under '
                'the name alone'))
        mode = realm['auth_mode']
        # ---- a code in a second window (1.0.76) ---------------------------
        # A token that gets its codes by mail or SMS always signs in so - the
        # password is the directory's and the code is asked for after it,
        # whatever the realm says of a code from the phone; a realm in the
        # "challenge" mode asks so of the app's tokens too. Everybody else
        # signs in exactly as before.
        challenge = None
        tok = self.store.token(d.token_name) if mode != 'password' else None
        kind = token_kind(tok) if tok else None
        if mode == 'challenge':
            if not tok:
                d.step('a token for %s' % d.token_name, False, SAY_NONE)
                d.acme = SAY_NONE
                return d.refuse('Denied by the token server: ' + SAY_NONE)
            challenge = kind
        elif tok and kind in ('mail', 'sms'):
            challenge = kind
        if challenge:
            if tok.get('state') == 'pending':
                d.step('the token of %s' % d.token_name, False, SAY_PENDING)
                d.acme = SAY_PENDING
                return d.refuse('Denied by the token server: ' + SAY_PENDING)
            if challenge in ('mail', 'sms') and challenge not in code_channels():
                why = ('sending mail is not set up' if challenge == 'mail'
                       else 'sending SMS is not set up')
                d.step('a code by %s' % ('mail' if challenge == 'mail' else 'SMS'), False, why)
                return d.refuse('Denied by the token server: the code cannot be sent - ' + why)
            d.step('the code comes in a second window', True,
                   'the token gets %s; the password is the directory password'
                   % CODE_KIND_WORDS[challenge])
        # ---- where the password ends and the code begins -------------------
        code, ad_password = None, None
        guessed = False
        if challenge:
            ad_password = password
        elif mode == 'acme':
            code = password
        elif mode == 'password_acme':
            tok = self.store.token(d.token_name)
            digits = int((tok or {}).get('digits') or CONFIG.get('totp_digits') or 6)
            splits = []
            if len(password) > digits:
                splits.append((password[-digits:], password[:-digits]))
            sd = int(CONFIG.get('scratch_digits') or 8)
            if len(password) > sd and sd != digits:
                splits.append((password[-sd:], password[:-sd]))
            if not splits:
                d.step('the code', False, 'nothing after the password looks like a code')
                d.acme = SAY_BAD
                return d.refuse('Denied by the token server: ' + SAY_BAD)
            code, ad_password = splits[0]
            if len(splits) > 1:
                guessed = splits[1][1]
                # Which one: the code that is right now, found with a dry
                # check that counts nothing and writes nothing - so one
                # password costs the directory one try, not two.
                for c, rest in splits:
                    ok, _said, _f = self.tokens.check(d.token_name, c, how=how, src=src,
                                                      rid=rid, dry=True, quiet=True)
                    if ok:
                        code, ad_password = c, rest
                        guessed = False
                        break
        # ---- the directory -----------------------------------------------
        entry = None
        lookup = realm.get('lookup') or ''
        if lookup not in ('upn', 'sam'):
            # No way chosen: by the form of the name. A realm with a directory
            # always asks it - its groups and a switched-off account are never
            # skipped because nobody picked how to look a name up.
            lookup = 'upn' if '@' in d.user else 'sam'
        if (realm.get('groups') or []) and not realm.get('directory'):
            d.step('the groups of %s' % d.user, False, 'the realm names groups and no directory '
                   'to ask them of')
            return d.refuse('account does not pass LDAP group filter(s): the realm %s has no '
                            'directory' % realm['name'])
        if realm.get('directory'):
            ad = self.directory(realm['directory'])
            if not ad:
                d.step('the directory %s' % realm['directory'], False, 'it is not set up')
                return d.refuse('the directory %s is not set up' % realm['directory'])
            t = time.time()
            try:
                entry = self.find_person(ad, d.user, lookup, realm)
            except LdapError as e:
                d.step('look %s up in %s' % (d.user, ad.name), False, str(e), t)
                return d.refuse('LDAP server(s) have gone away' if isinstance(
                    e, LdapUnreachable) else 'the directory could not be asked: %s' % e)
            if not entry:
                d.step('look %s up in %s' % (d.user, ad.name), False,
                       'by %s: there is no such account' % {'upn': 'userPrincipalName',
                                                           'sam': 'sAMAccountName'}.get(lookup,
                                                                                         lookup),
                       t)
                return d.refuse('account does not pass LDAP user filter: %s is not in %s'
                                % (d.user, ad.name))
            d.display = entry.get('display') or ''
            if entry.get('many'):
                # Two accounts answer to the name (1.0.57): which one would
                # be checked is chance, so neither is.
                d.step('look %s up in %s' % (d.user, ad.name), False,
                       'more than one account answers to the name', t)
                return d.refuse('more than one account in %s answers to %s'
                                % (ad.name, d.user))
            d.step('found %s' % entry['dn'], True, entry.get('display') or '', t)
            if realm.get('check_disabled', 1):
                why = entry_unusable(entry)
                if why:
                    d.step('the account is in use', False, why)
                    if entry.get('disabled'):
                        return d.refuse('the account is disabled in the directory')
                    if entry.get('expires') and entry['expires'] < time.time():
                        return d.refuse('the account has expired in the directory')
                    return d.refuse('the account may not sign in: %s' % why)
            if mode in ('password', 'password_acme') or challenge:
                pw = password if mode == 'password' else ad_password
                if code is not None or challenge:
                    # A token locked out or paused is refused before its
                    # password is tried in the directory (1.0.57).
                    stop = self.tokens.blocked(d.token_name)
                    if stop:
                        d.step('the code for the token %s' % d.token_name, False, stop)
                        return d.refuse('Denied by the token server: ' + stop)
                t = time.time()
                try:
                    ad.password_ok(entry, pw)
                    d.step('the directory password', True, '', t)
                except LdapError as e:
                    d.step('the directory password', False, str(e), t)
                    if guessed and not isinstance(e, LdapUnreachable) and \
                            int((tok or {}).get('scratch_left') or 0) > 0:
                        # No split gave a right code, and the password before
                        # a code from the phone was refused (1.0.101). If the
                        # password was right, what followed it was a wrong
                        # recovery code - nothing counted that before, past
                        # the pause and the lockout. The directory is not asked
                        # twice to find out (a typo would count twice there);
                        # each such request is counted towards the token's
                        # recovery codes instead: past a day's few, they are
                        # not taken for a while. Codes from the app go on.
                        scratch_guard_note(self.store, d.token_name,
                                           getattr(REQUEST_PLACE, 'v', ''))
                    return d.refuse('the directory refused the password: %s' % e
                                    if not isinstance(e, LdapUnreachable)
                                    else 'LDAP server(s) have gone away')
            wanted = realm.get('groups') or []
            if wanted:
                t = time.time()
                try:
                    have = ad.groups_of(entry, bool(realm.get('nested', 1)))
                except LdapError as e:
                    d.step('the groups of %s' % d.user, False, str(e), t)
                    return d.refuse('LDAP server(s) have gone away')
                try:
                    hit = group_matches(wanted, have, ad)
                except LdapError as e:
                    d.step('the group of %s looked up' % d.user, False, str(e), t)
                    return d.refuse('LDAP server(s) have gone away')
                if not hit:
                    names = ', '.join(cn_of(w.get('group') or '') or w.get('group') or ''
                                      for w in wanted[:6]) + (' …' if len(wanted) > 6 else '')
                    d.step('a member of one of %d group(s)' % len(wanted), False,
                           'a member of %d group(s)%s, none of them one of: %s'
                           % (len(have), ' (nested counted)' if realm.get('nested', 1) else '',
                              names), t)
                    return d.refuse('account does not pass LDAP group filter(s): %s is in '
                                    'none of %s' % (d.user, names))
                d.step('a member of %s' % hit['group'], True, '', t)
                try:
                    d.reply.extend(reply_lines(hit.get('reply') or ''))
                except RadiusError as e:
                    # Never an Accept without what limits it (1.0.57).
                    d.step('the answer of the group %s' % hit['group'], False, str(e))
                    return d.refuse('the answer for the group cannot be built: %s' % e)
        elif mode in ('password', 'password_acme') or challenge:
            d.step('the directory password', False, 'the realm has no directory to ask')
            return d.refuse('the realm %s has no directory' % realm['name'])
        if challenge:
            try:
                reply = reply_lines(realm.get('reply') or '') + d.reply
            except RadiusError as e:
                d.step('the answer', False, str(e))
                return d.refuse('the answer of the realm cannot be built: %s' % e)
            return self.challenge_start(d, realm, tok, challenge, reply, client, src, rid)
        # ---- the code, last ----------------------------------------------
        if code is not None:
            t = time.time()
            ok, said, facts = self.tokens.check(d.token_name, code, how=how, src=src, rid=rid)
            d.acme = said
            d.step('the code for the token %s' % d.token_name, ok, said, t)
            if not ok:
                return d.refuse('Denied by the token server: ' + said)
        try:
            d.reply = reply_lines(realm.get('reply') or '') + d.reply
        except RadiusError as e:
            d.step('the answer', False, str(e))
            return d.refuse('the answer of the realm cannot be built: %s' % e)
        d.result = 'accept'
        d.step('let in', True, ', '.join('%s = %s' % p for p in d.reply))
        return d


    # ---- the second window (1.0.76) ----------------------------------------------
    def challenge_start(self, d, realm, tok, kind, reply, client, src, rid):
        """The password was right: a code sent (mail, SMS) or asked for (the
        app), and an Access-Challenge to say so."""
        name = d.token_name
        data = {'name': name, 'user': d.user, 'realm': realm['name'],
                'client': (client or {}).get('id'), 'kind': kind,
                'reply': [list(p) for p in reply], 'src': src,
                # What the first request proved (1.0.118), for the second
                # one's decision to show: the account, its password, its group.
                'checked': [str(one.get('what') or '')[:200] for one in d.steps
                            if one.get('ok') and not str(one.get('what') or '').startswith(
                                ('the realm is', 'the name is read', 'the code comes'))][:8],
                'rid': str(rid or '')[:120]}
        if kind in ('mail', 'sms'):
            dest = str(tok.get('dest') or '')
            if not dest:
                d.step('where the code goes', False, 'the token has no address or number')
                return d.refuse('Denied by the token server: the token has nowhere to send '
                                'a code')
            if not code_send_allowed(self.store, name):
                said = ('%d codes were sent in %d min already'
                        % (int(CONFIG.get('code_send_max') or 5),
                           int(CONFIG.get('code_send_window_min') or 15)))
                d.step('a code sent', False, said)
                d.acme = 'Too many codes sent'
                return d.refuse('Denied by the token server: too many codes sent - ' + said)
            code = code_new()
            data['code'] = code_hash(name, code)
            data['dest'] = dest          # the answer checks the token still sends there (1.0.94)
            d.state = chal_new(self.store, data)
            code_send_later(self.store, kind, dest, code, name, rid)
            d.message = code_words('ask_' + kind, lang=token_lang(tok), dest=dest_masked(kind, dest))
            d.step('a code sent by %s to %s' % ('mail' if kind == 'mail' else 'SMS',
                                                 dest_masked(kind, dest)), True,
                   'good for %d s' % int(CONFIG.get('code_ttl_s') or 300))
            d.acme = 'Code sent by %s' % ('mail' if kind == 'mail' else 'SMS')
        else:
            d.state = chal_new(self.store, data)
            d.message = code_words('ask_totp', lang=token_lang(tok))
            d.step('the code from the app asked for', True, '')
            d.acme = 'Code asked for'
        d.result = 'challenge'
        d.reason = 'the code is asked for in a second window'
        return d

    def answer(self, user, password, state, client_realm='', src='', rid='', chap=False,
               how='radius', client=None):
        """The second Access-Request: the code typed into the second window,
        with the State of the challenge."""
        d = Decision()
        d.user = self.full_name(user, client_realm or CONFIG.get('default_realm') or '')
        chal, raw = chal_get(self.store, state)
        if not chal:
            d.step('the question this answers', False, 'there is none - it was answered, or '
                   'ran out, or was asked by another server')
            return d.refuse('the code was asked for too long ago: sign in again')
        d.realm = chal.get('realm') or ''
        d.token_name = name = chal.get('name') or ''
        kind = chal.get('kind') or 'totp'
        if float(chal.get('exp') or 0) < time.time():
            chal_take(self.store, state, raw)
            d.step('the question this answers', False, 'it ran out %s' % stamp(chal.get('exp')))
            d.acme = 'The code ran out'
            return d.refuse('Denied by the token server: the code ran out - sign in again')
        if norm_name(chal.get('user') or '') != norm_name(d.user) or \
                chal.get('client') != (client or {}).get('id'):
            d.step('the question this answers', False, 'it was asked of another name or through '
                   'another client')
            return d.refuse('the answer does not belong to the question it names')
        d.step('the answer to the code asked for: %s' % CODE_KIND_WORDS.get(kind, kind), True,
               'asked %s' % stamp(chal.get('made')))
        if chal.get('checked'):
            # Checked once, with the first request (1.0.118): the second
            # carries the code alone, and is let in on what the first proved.
            d.step('checked with the first request%s' % (
                ' (%s)' % chal['rid'] if chal.get('rid') else ''), True,
                '; '.join(chal['checked']))
        if chap or not password:
            d.step('the code', False, 'nothing came, or not as PAP')
            return d.refuse('the request carries no code (PAP)')
        code = str(password).strip()
        t = time.time()
        # A try is taken before the code is looked at (1.0.101): written to
        # the question with a conditional update, so of answers that came
        # at the same moment only as many as there are tries are compared -
        # not all of them, each having read "0 tries so far".
        limit = int(CONFIG.get('code_tries') or 3)
        for _round in range(64):
            if int(chal.get('tries') or 0) >= limit:
                chal_take(self.store, state, raw)
                d.step('the code for the token %s' % name, False, 'no tries left', t)
                d.acme = SAY_RATE
                return d.refuse('Denied by the token server: no tries left - sign in again')
            nxt = dict(chal)
            nxt['tries'] = int(chal.get('tries') or 0) + 1
            if chal_put(self.store, state, raw, nxt):
                chal, raw = nxt, json.dumps(nxt)
                break
            chal, raw = chal_get(self.store, state)
            if not chal:
                d.step('the question this answers', False, 'answered meanwhile')
                return d.refuse('the code was asked for too long ago: sign in again')
        else:
            return d.refuse('Denied by the token server: too many answers at once')
        if kind in ('mail', 'sms'):
            stop = self.tokens.blocked(name)
            # The token as it is now (1.0.94): taken away, made anew for the
            # app, or sending elsewhere since - the code sent is nothing then.
            now_tok = self.store.token(name)
            if not stop and (not now_tok or token_kind(now_tok) != kind or (
                    chal.get('dest') and str(now_tok.get('dest') or '') != chal.get('dest'))):
                stop = 'the token changed since the code was sent - sign in again'
            if stop:
                chal_take(self.store, state, raw)
                d.step('the code for the token %s' % name, False, stop, t)
                d.acme = stop
                return d.refuse('Denied by the token server: ' + stop)
            if re.fullmatch(r'[0-9]{4,10}', code, re.ASCII) and \
                    hmac.compare_digest(code_hash(name, code), str(chal.get('code') or '')):
                ok, said = True, 'Code sent by %s accepted' % ('mail' if kind == 'mail' else 'SMS')
                if once_take(self.store, 'chal', name, hashlib.sha256(bytes(state)).hexdigest()):
                    chal_drop(self.store, state)
                    self.tokens.used_sent(name, kind)
                    self.tokens._said(name, True, said, how, src, rid)
                else:
                    ok, said = False, SAY_REUSED
            else:
                # A recovery code - or a wrong code, counted as one from the
                # phone is, towards the lockout.
                ok, said, _f = self.tokens.check(name, code, how=how, src=src, rid=rid)
                if ok:
                    chal_drop(self.store, state)
        else:
            # The code is taken once by the token itself (its step, once_take):
            # the question is done with, even if a second answer to it counted
            # a try meanwhile - that refused the right code and used it up.
            ok, said, _f = self.tokens.check(name, code, how=how, src=src, rid=rid)
            if ok:
                chal_drop(self.store, state)
        d.acme = said
        d.step('the code for the token %s' % name, ok, said, t)
        if ok:
            d.reply = [tuple(p) for p in chal.get('reply') or []]
            d.result = 'accept'
            d.step('let in', True, ', '.join('%s = %s' % p for p in d.reply))
            return d
        if said == SAY_REUSED or chal['tries'] >= limit or self.tokens.blocked(name):
            chal_take(self.store, state, raw)
            return d.refuse('Denied by the token server: ' + said)
        d.state = state
        d.message = code_words('again', lang=token_lang(self.store.token(name)))
        d.result = 'challenge'
        d.reason = 'the code was not right: asked again (%d of %d)' % (
            chal['tries'], limit)
        return d


