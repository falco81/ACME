# -*- coding: utf-8 -*-
"""
The "Certificates" menu of the console (acme --console), at the top of the
main menu. As every other menu there, it only runs `acme ...` commands of the
command line (acmelib/certs/cli.py) - nothing here can do more than they do,
and what the pages can do, it can do.

    c  Certificates
         1 Browse them (Enter: show, renew, deploy, deployments, edit, export,
                        CSR and its answer, revoke, delete)
         2 Add one                         3 Renew what is due now
         k Check names before a certificate (what to set up where; a dry run)
         4 Jobs (Enter: followed live)     5 The live log of the certificates
         6 Sources        7 Validations    8 Targets
                          (Enter: show, edit, test, its actions, delete; + add one)
         9 Deployments (Enter: run, edit, switch, delete)
         t Tests (Enter: show, edit, try, delete; + add one) - and on a certificate:
           its tests (attach, run, after which deployment, switch, take off)
         a Authorities (show, CRL, export, sign a CSR, revoke, delete; new root,
                        new intermediate, import)
         d acme's DNS server (its records: add, delete)
         0 Modules (Enter: what one takes)
    o  Owners and teams (1.0.126): the tree (Enter: show, members and their roles, change,
       limits, move, a team below, activity, delete; + add one), roles, the access check
       of a person, what happened in a team

A module's form is drawn from its `fields` (acme --plugin KIND --json): a
choice for a select and an on/off, a secret typed as stars and handed over
in the environment (ACME_VALUE_KEY, --set KEY=@env), never on a command line;
a PEM read from a file (@file:PATH).
"""
from __future__ import annotations

import json
import os
import re
import time

FAMS = {'issuer': ('source', 'sources', 'Sources: where certificates come from'),
        'challenge': ('validation', 'validations', 'Validations: how names are proved'),
        'target': ('target', 'targets', 'Targets: where certificates go'),
        'check': ('check', 'tests', 'Tests: is each certificate served where it should be')}
CONNECTOR = 'ssh_connector'


def main_items(con):
    return [('c', 'Certificates: renewing, deploying, authorities, DNS', lambda: menu(con)),
            # 1.0.126: Settings → Owners and teams of the pages (acme --teams, --roles, ...)
            ('o', 'Owners and teams: the tree, members, roles, limits, access',
             lambda: teams_menu(con))]


def _when(ts, fmt='%Y-%m-%d'):
    if not ts:
        return '-'
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)


TONES = {'ok': 'ok', 'failed': 'bad', 'expired': 'bad', 'revoked': 'dim', 'disabled': 'dim',
         'new': 'warn', 'pending': 'warn', 'renewing': 'warn', 'due': 'warn',
         'deploying': 'warn', 'changed': 'warn', 'outdated': 'warn'}


def _tone(r):
    if r.get('days_left') is not None and r['days_left'] < 14 and r.get('state') == 'ok':
        return 'warn'
    return TONES.get(r.get('state') or '', '')


def menu(con):
    def load():
        return con._rows(con.out('--certs'), 'rows')

    cols = [('certificate', lambda r: r.get('name'), 28, None),
            ('state', lambda r: r.get('state') or '', 9, _tone),
            ('left', lambda r: '-' if r.get('days_left') is None else '%d d' % r['days_left'], 6,
             _tone),
            ('issuer', lambda r: r.get('issuer') or '-', 16, None),
            ('names', lambda r: ', '.join(r.get('names') or []), 50, lambda r: 'dim')]
    return con.sub('Certificates', [
        ('1', 'Browse them (Enter: what to do with one)',
         lambda: con.pick('Certificates', load, cols, lambda r: cert_do(con, r),
                          'no certificate yet')),
        ('i', 'Import one: a file (a new version of one: from its own menu)', lambda: cert_import(con)),
        ('s', 'A self-signed certificate', lambda: cert_selfsigned(con)),
        ('2', 'Add one', lambda: cert_add(con)),
        ('k', 'Check names before a certificate: what to set up where', lambda: check_names(con)),
        ('3', 'Renew every one that is due, now', lambda: con.act('--renew', 'all')),
        ('4', 'Jobs (Enter: every step, live)', lambda: jobs(con)),
        ('5', 'The live log of the certificates', lambda: live_log(con)),
        ('6', FAMS['issuer'][2], lambda: family(con, 'issuer')),
        ('7', FAMS['challenge'][2], lambda: family(con, 'challenge')),
        ('8', FAMS['target'][2], lambda: family(con, 'target')),
        ('g', 'Target agents: enrollment codes, agents waiting for confirmation',
         lambda: agents_menu(con)),
        ('9', 'Deployments: which certificate goes where', lambda: deploys(con)),
        ('t', FAMS['check'][2], lambda: family(con, 'check')),
        ('r', 'Run the tests of every certificate (a report by mail or SMS if wanted)',
         lambda: run_tests(con, 'all', 'every test')),
        ('a', 'Authorities of acme\'s own', lambda: cas(con)),
        ('d', 'acme\'s own DNS server', lambda: dns(con)),
        ('n', 'DNS sets: which DNS servers each function asks (Settings → DNS)',
         lambda: con.act('--dns-sets')),
        ('0', 'Modules (Enter: what one takes)', lambda: modules(con)),
    ])


def live_log(con):
    """The daemon's log, only the certificates' lines (and the jobs' steps go
    with Jobs, live)."""
    fn = getattr(con, 'live_log', None)
    if fn is None:
        return con.act('--events', '--search', 'certificates')
    con.live(lambda: fn('certificates'))


# ---------------------------------------------------------------------------
# A module's form, from its fields
# ---------------------------------------------------------------------------
def _norm(v):
    if isinstance(v, bool):
        return '1' if v else '0'
    s = str(v if v is not None else '')
    return {'true': '1', 'false': '0', 'yes': '1', 'no': '0', 'on': '1', 'off': '0'}.get(
        s.lower(), s)


def _shown(f, vals):
    for k, want in (f.get('show_if') or {}).items():
        if _norm(vals.get(k, '')) not in [_norm(x) for x in (want or [])]:
            return False
    return True


NL = ' \u23ce '            # a line's end, as one line of a form shows it (1.0.77)


def _text_of(f, v):
    if v is None:
        return ''
    if isinstance(v, (list, tuple)):
        return ', '.join(str(x) for x in v)
    if f.get('type') == 'bool':
        return _norm(v)
    if f.get('type') == 'list' and '\n' in str(v):
        return ', '.join(x.strip() for x in str(v).splitlines() if x.strip())
    return str(v).replace('\r', '').replace('\n', NL)


def _form_fields(fields, cur, secret_set, base=None):
    """`base`: the values of the form before this one ("More" after the main one), which a
    field's show_if may name (1.0.77: those were never shown under More)."""
    out = []
    for f in fields:
        t = f.get('type') or 'text'
        if f.get('secret') and t not in ('pem', 'secret'):
            t = 'secret'            # an SSH key (sshkey) and others kept secret: typed unseen
        if t == 'secret' and f.get('multiline'):
            # a key or JSON of several lines (ms_adcs client_key, step_ca provisioner_key,
            # 1.0.126): read from a file as a PEM is - a line of a form ended at the first
            # line's end, and only that line was saved
            t = 'pem'
        have = cur.get(f['key'], f.get('default'))
        one = {'key': f['key'], 'label': (f.get('label') or f['key'])[:28],
               'help': f.get('help') or ''}
        if t == 'select' and f.get('options'):
            opts = [(str(o[0]), str(o[1] if len(o) > 1 else o[0])) for o in f.get('options') or []]
            if f.get('from_bool') and _norm(have) in ('1', '0'):
                have = f['from_bool'][0] if _norm(have) == '1' else f['from_bool'][1]
            if not f.get('required'):
                opts = [('', '–')] + [o for o in opts if o[0] != '']
            now = _text_of(f, have)
            # What is set now and not offered (a CA switched off, a value of before): kept
            # as a choice of its own - it was taken as the first one and saved (1.0.77).
            if now and now not in [o[0] for o in opts]:
                opts.insert(0, (now, '%s (as it is - not offered now)' % now))
            one.update(kind='choice', options=opts, value=now)
        elif t == 'bool':
            one.update(kind='choice', options=[('1', 'yes'), ('0', 'no')],
                       value=_norm(have if have not in (None, '') else False))
        elif t == 'secret':
            # Typed as stars; the one kept as dots and its last two (root's console).
            one.update(kind='secret', value='',
                       help=('(set: %s - empty keeps it) ' % (
                           have if isinstance(have, str) and have.startswith('\u2022') else
                           '\u2022' * 8) if f['key'] in secret_set else '') + one['help'])
        elif t == 'pem':
            one.update(value='', help='A file on this machine to read it from (or empty to '
                       'keep it as it is). ' + one['help'])
            one['label'] = (f.get('label') or f['key'])[:20] + ' (file)'
        elif t == 'list':
            one.update(value=_text_of(f, have), help='Comma between them. ' + one['help'])
        elif t == 'number':
            one.update(value=_text_of(f, have),
                       check=lambda v, _vals: None if re.match(r'^-?\d+(\.\d+)?\Z', v)
                       else 'a number')
        else:
            one.update(value=_text_of(f, have))
        if f.get('required') and t not in ('secret', 'pem') and \
                f.get('default') in (None, '', []):
            one['need'] = True
        if f.get('show_if'):
            one['when'] = (lambda vals, _f=f: _shown(_f, dict(base or {}, **vals)))
        out.append(one)
    return out


def module_form(con, title, fields, cur=None, secret_set=(), words=''):
    """The fields asked for (the main ones, then - when wanted - those under
    "More"). Returns (argv of --set, env) of what changed, or None (Esc). `cur` given (even
    empty - a deployment made with no options): what is set now, only changes are said."""
    editing = cur is not None
    cur = dict(cur or {})
    main = [f for f in fields if not f.get('advanced')]
    more = [f for f in fields if f.get('advanced')]
    got = {}
    if main:
        g = con.form(title, _form_fields(main, cur, secret_set), words)
        if g is None:
            return None
        got.update(g)
    if more and con.confirm('More', 'Change the settings under "More" too (%s)?' % ', '.join(
            f['key'] for f in more)[:300], 'Yes', 'No'):
        g = con.form(title + ' - more', _form_fields(more, dict(cur, **got), secret_set,
                                                     base=dict({k: _text_of({}, v) for k, v
                                                                in cur.items()}, **got)))
        if g is None:
            return None
        got.update(g)
    argv, env = [], {}
    by_key = {f['key']: f for f in fields}
    for k, v in got.items():
        f = by_key[k]
        t = f.get('type') or 'text'
        if f.get('secret') and t not in ('pem', 'secret'):
            t = 'secret'
        if t == 'secret' and f.get('multiline'):
            t = 'pem'               # read from a file, as above
        if t == 'secret':
            if v:
                env['ACME_VALUE_' + re.sub(r'[^A-Za-z0-9]', '_', k).upper()] = v
                argv += ['--set', '%s=@env' % k]
            continue
        if t == 'pem':
            if v.strip():
                argv += ['--set', '%s=@file:%s' % (k, os.path.expanduser(v.strip()))]
            continue
        if editing:
            # Changed: only what differs from what is set now (hunt R u5: a deployment with no
            # options of its own was given every default - mode=new admin=0 ... - when its
            # form was opened and left as it was, and so deployed again)
            if v == _text_of(f, cur.get(k, f.get('default'))):
                continue
        elif v == '':
            continue
        if t == 'list':
            v = '\n'.join(x.strip() for x in v.split(',') if x.strip())
        else:
            v = v.replace(NL, '\n')
        argv += ['--set', '%s=%s' % (k, v)]
    return argv, env


def _plugin(con, fam, kind):
    got = con.out('--plugin', '%s/%s' % (fam, kind)) or {}
    mods = got.get('modules') or []
    return mods[0] if mods else None


# ---------------------------------------------------------------------------
# Sources, validations, targets
# ---------------------------------------------------------------------------
def family(con, fam):
    word, path, title = FAMS[fam]

    def load():
        return [{'name': '+ add a %s' % ('test' if fam == 'check' else word), 'kind': '',
                 '_add': True}] + \
            con._rows(con.out('--' + path), 'rows')

    cols = [('test' if fam == 'check' else word,
             lambda r: r.get('name') + (' *' if r.get('is_default') else ''), 28,
             lambda r: 'ok' if r.get('_add') else None),
            ('kind', lambda r: r.get('kind'), 14, None),
            ('', lambda r: '' if r.get('_add') else ('on' if r.get('enabled', 1) else 'off'), 3,
             lambda r: '' if r.get('enabled', 1) else 'dim'),
            ('used by', lambda r: '' if r.get('_add') else r.get('used_by'), 7, None),
            ('last error', lambda r: r.get('last_error') or '', 50,
             lambda r: 'bad' if r.get('last_error') else 'dim')]
    if fam in ('target', 'check'):
        # the team whose device it is (1.0.126, as the pages' Owner column); a test's team too
        # (1.0.128 - hunt R u5: the console could neither show nor set it)
        cols.insert(4, ('owner', lambda r: r.get('owner') or '', 14, lambda r: 'dim'))

    def do(r):
        if r.get('_add'):
            return fam_add(con, fam)
        return fam_do(con, fam, r)
    return con.pick(title, load, cols, do, 'none yet',
             '* the default: what a new certificate takes when none is said' if fam != 'target'
             else '* the default: offered first for a new deployment')


def fam_add(con, fam):
    word, path, _t = FAMS[fam]
    mods = con._rows(con.out('--plugins'), fam)
    if not mods:
        con.note('No module', 'There is no %s module (acme --plugins).' % word, 'bad')
        return
    kind = con.choose('Which kind of %s' % word, [(d['kind'], '%s  (%s)' % (d['title'], d.get(
        'vendor') or d['kind'])) for d in mods])
    if not kind:
        return
    d = _plugin(con, fam, kind) or {}
    name = con.ask_one('A new %s' % word, 'its name', '', 'What acme calls it - certificates '
                       'and deployments refer to it by this name.')
    if not name:
        return
    got = module_form(con, '%s %s (%s)' % (word, name, kind), d.get('fields') or [],
                      words=d.get('description') or '')
    if got is None:
        return
    argv, env = got
    if fam in ('target', 'check'):
        # the team whose device (1.0.126) or test (1.0.128) it is; asked only when there are teams
        owner = _team_choice(con, 'Whose %s is %s' % ('device' if fam == 'target' else 'test',
                                                      name), '', none="acme's own - no team")
        if owner is None:
            return
        if owner:
            argv = list(argv) + ['--owner', owner]
    rc = con.act('--%s-add' % word, name, '--kind', kind, *argv, env=env)
    if rc == 0 and fam != 'target' and con.confirm('Try it', 'Try %s now, changing nothing?'
                                                   % name, 'Try it', 'Later'):
        con.live(lambda: (con.cmd('--%s-test' % word, name), con.pause()))
    elif rc == 0 and fam == 'target' and con.confirm('Try it', 'Reach %s, sign in, change '
                                                     'nothing?' % name, 'Try it', 'Later'):
        con.live(lambda: (con.cmd('--target-test', name), con.pause()))


def fam_do(con, fam, r):
    word, path, _t = FAMS[fam]
    name = r['name']
    opts = [('show', 'Show it all'), ('test', 'Try it (nothing is changed)'),
            ('edit', 'Change its settings'), ('rename', 'Rename it'),
            ('switch', 'Switch it %s' % ('off' if r.get('enabled', 1) else 'on')),
            ('default', 'No default %s any more' % word if r.get('is_default') else
             'Make it the default %s' % word)]
    if fam == 'challenge' and r.get('kind') == 'http_local':
        opts.append(('check', 'Check a name (HTTP-01 from here)'))
    if (_plugin(con, fam, r.get('kind')) or {}).get('discover'):
        opts.append(('discover', 'Find the settings from the account'))
    for a in r.get('actions') or []:
        opts.append(('act:' + a['key'], a.get('label') or a['key']))
    if fam == 'target' and r.get('kind') != CONNECTOR:
        opts.append(('deploys', 'Its deployments'))
    if fam in ('target', 'check'):
        opts.append(('owner', 'Its owner: the team whose %s it is (now: %s)'
                     % ('device' if fam == 'target' else 'test', r.get('owner') or "acme's own")))
    if fam == 'check':
        opts.append(('run', 'Run it now on every certificate it is attached to'))
    if any(f.get('type') == 'sshkey' for f in (_plugin(con, fam, r.get('kind')) or {}).get(
            'fields') or []):
        opts.append(('key', 'Its SSH key (make, public half, your own, forget, try)'))
    if fam == 'target' and r.get('kind') in ('agent', 'agent_windows'):
        opts.append(('agent', 'Its acme-agent (state, join code, confirm, ask it, policy, '
                              'renew, update, forget)'))
    opts.append(('del', 'Delete it'))
    what = con.choose(name, opts, '%s, used by %s' % (r.get('kind'), r.get('used_by') or 0))
    if what == 'show':
        con.act('--%s-show' % word, name)
    elif what == 'test':
        flag = '--target-test' if fam == 'target' else '--%s-test' % word
        con.live(lambda: (con.cmd(flag, name), con.pause()))
    elif what == 'edit':
        d = _plugin(con, fam, r.get('kind')) or {}
        got = module_form(con, '%s %s (%s)' % (word, name, r.get('kind')),
                          d.get('fields') or [], r.get('config') or {},
                          r.get('secret_set') or [])
        if got is None:
            return
        argv, env = got
        if not argv:
            con.note('Nothing changed', 'Nothing was changed.')
            return
        con.act('--%s-edit' % word, name, *argv, env=env)
    elif what == 'discover':
        # what the account says (read-only), shown; then, if asked, saved into the empty ones
        con.live(lambda: (con.cmd('--%s-discover' % word, name), con.pause()))
        if con.confirm('Fill it in', 'Save what was found into the settings of %s that are '
                       'empty? Nothing set is replaced; a list is chosen by its settings '
                       '(Change its settings).' % name, 'Fill it in'):
            con.act('--%s-discover' % word, name, '--fill')
    elif what == 'rename':
        new = con.ask_one('Rename %s' % name, 'its new name', name)
        if new and new != name:
            con.act('--%s-edit' % word, name, '--name', new)
    elif what == 'switch':
        con.act('--%s-edit' % word, name, '--enabled', 'off' if r.get('enabled', 1) else 'on')
    elif what == 'default':
        con.act('--%s-default' % word, 'none' if r.get('is_default') else name)
    elif what == 'check':
        host = con.ask_one('Check a name', 'the name', '', 'acme puts a probe token in place '
                           'and fetches http://NAME/.well-known/acme-challenge/ from here.')
        if host:
            con.live(lambda: (con.cmd('--validation-check', name, host), con.pause()))
    elif what and what.startswith('act:'):
        key = what[4:]
        a = next((x for x in r.get('actions') or [] if x['key'] == key), {})
        if con.confirm(a.get('label') or key, a.get('confirm') or a.get('help') or
                       'Run %s on %s?' % (key, name), 'Run it'):
            con.live(lambda: (con.cmd('--%s-action' % word, name, key, '--yes'), con.pause()))
    elif what == 'deploys':
        return deploy_list(con, target=name)
    elif what == 'owner':
        owner = _team_choice(con, 'The owner of %s' % name, r.get('owner') or '',
                             none="acme's own - no team", always=True)
        if owner is not None and owner.lower() != (r.get('owner') or '').lower():
            con.act('--%s-edit' % word, name, '--owner', owner or '-')
    elif what == 'run':
        run_tests(con, 'test:' + name, 'the test %s on its certificates' % name)
    elif what == 'key':
        ssh_key(con, word, name)
    elif what == 'agent':
        target_agent(con, name, r.get('kind'))
    elif what == 'del':
        used = int(r.get('used_by') or 0)
        if used and word in ('target', 'check'):
            # used somewhere (1.0.88, as the pages): taken off there first, then deleted
            if con.confirm('Delete %s' % name, '%s is used in %d place(s) (acme --%s-del %s lists '
                           'them). Take it off everywhere first - %s - and then delete it?'
                           % (name, used, word, name, 'its deployments are deleted, the '
                              'certificates stay where they were put' if word == 'target'
                              else 'it is taken off its certificates and tests'),
                           'Take it off and delete it', danger=True):
                con.act('--%s-del' % word, name, '--force', '--yes')
        elif con.confirm('Delete %s' % name, 'Delete the %s %s with its settings and secrets?'
                         % (word, name), 'Delete it', danger=True):
            con.act('--%s-del' % word, name, '--yes')
    return None


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
def cert_do(con, r):
    name = r['name']
    by_hand = not r.get('issuer')
    # By hand (imported, a CSR): nothing to renew it from, nothing to validate (1.0.75 on the
    # page, 1.0.77 here).
    opts = [('show', 'Show it all')] + ([] if by_hand else [('renew', 'Renew it now')]) + [
        ('deploy', 'Deploy it now')] + ([] if by_hand else [
            ('check', 'Check its validation: what to set up where'),
            ('dry', 'A dry run of its validation (no CA asked)')]) + [
        ('deploys', 'Its deployments (add, run, change, take away)'),
        ('tests', 'Its tests (attach, run, after which deployment, switch, take off)'),
        ('edit', 'Change it (names, issuer, validation, renewing)'),
        ('source', 'Change the source (imported, an authority, by hand) - keeping the rest'),
        ('switch', 'Switch it %s' % ('off' if r.get('enabled', 1) else 'on')),
        ('hold', 'Deploy hold: %s' % ('on - a new one waits for Deploy it now' if r.get(
            'deploy_hold') else 'off - a new one is deployed by itself')),
        ('import', 'A new version of it from a file'),
        ('export', 'Export it into a file'), ('csr', 'A CSR for an outside authority'),
        ('answer', 'The answer to its CSR (a file)'), ('revoke', 'Revoke it'),
        ('del', 'Delete it')]
    what = con.choose(name, opts, '%s, %s, ends %s' % (r.get('state'), r.get('issuer') or
                                                        'imported', _when(r.get('not_after'))))
    if what == 'show':
        con.act('--cert', name)
    elif what == 'check':
        con.live(lambda: (con.cmd('--cert-check', name), con.pause()))
    elif what == 'dry':
        con.live(lambda: (con.cmd('--dry-run', name), con.pause()))
    elif what in ('renew', 'deploy'):
        con.live(lambda: (con.cmd('--' + what, name), con.pause()))
    elif what == 'deploys':
        return deploy_list(con, cert=name)
    elif what == 'tests':
        return cert_tests(con, name)
    elif what == 'edit':
        cert_edit(con, r)
    elif what == 'source':
        cert_source(con, r)
    elif what == 'switch':
        con.act('--cert-edit', name, '--enabled', 'off' if r.get('enabled', 1) else 'on')
    elif what == 'hold':
        con.act('--deploy-hold', name, 'off' if r.get('deploy_hold') else 'on')
    elif what == 'import':
        cert_import(con, name)
    elif what == 'export':
        got = con.form('Export ' + name, [
            {'key': 'format', 'label': 'format', 'kind': 'choice', 'options': [
                ('fullchain-pem', 'the certificate and its chain (PEM)'),
                ('cert-pem', 'the certificate (PEM)'), ('cert-der', 'the certificate (DER)'),
                ('chain-pem', 'the chain (PEM)'), ('p7b', 'PKCS#7 (P7B)'),
                ('combined-pem', 'key + certificate + chain (PEM)'),
                ('pfx', 'PKCS#12 (PFX), locked'), ('jks', 'Java keystore (JKS), locked'),
                ('key-pem', 'the private key (PEM)')]},
            {'key': 'out', 'label': 'into the file', 'value': '/root/%s.pem' % name,
             'need': True}])
        if got:
            args = ['--export', name, '--format', got['format'], '--out', got['out']]
            if got['format'] in ('pfx', 'jks'):
                con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
            else:
                con.act(*args)
    elif what == 'csr':
        out = con.ask_one('A CSR for ' + name, 'into the file', '/root/%s.csr' % name,
                          'The request is written there; the key waits in acme for the answer.')
        if out:
            con.act('--csr', name, '--out', out)
    elif what == 'answer':
        f = con.ask_one('The answer to the CSR of ' + name, 'the file', '/root/%s.pem' % name,
                        'The certificate the authority sent back (PEM, DER, P7B).')
        if f:
            con.live(lambda: (con.cmd('--csr-answer', name, f), con.pause()))
    elif what == 'revoke':
        got = con.form('Revoke ' + name, [
            {'key': 'reason', 'label': 'why', 'kind': 'choice', 'options': [
                (x, x) for x in ('unspecified', 'keyCompromise', 'superseded',
                                 'cessationOfOperation', 'affiliationChanged',
                                 'privilegeWithdrawn')]}],
            'It is revoked where it was issued, and cannot be taken back.')
        if got and con.confirm('Revoke ' + name, 'Revoke %s (%s)?' % (name, got['reason']),
                               'Revoke it', danger=True):
            con.live(lambda: (con.cmd('--revoke', name, '--reason', got['reason'], '--yes'),
                              con.pause()))
    elif what == 'del':
        if con.confirm('Delete ' + name, 'Delete %s, its versions and its deployments? Where '
                       'it is deployed stays as it is.' % name, 'Delete it', danger=True):
            con.act('--cert-del', name, '--yes')
    return None


def check_names(con):
    """Names checked before a certificate: grouped by domain, what each
    validation needs where, the records to create - then a dry run if wanted."""
    vals = _names_of(con, '--validations')
    got = con.form('Check names before a certificate', [
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'help': 'The names the certificate is to have, from any domains.'},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice',
         'options': [('', '– (the default, or as acme suggests)')] + vals,
         'help': 'How they are to be proved; acme also says which others would do.'}],
        'Nothing is changed: DNS and the validations are asked, read only.')
    if not got:
        return
    args = ['--check-names', got['names']]
    if got.get('challenge'):
        args += ['--challenge', got['challenge']]
    rc = []
    con.live(lambda: (rc.append(con.cmd(*args)), con.pause()))
    if rc and rc[0] != 0:
        return              # the names could not be checked: no dry run offered (1.0.77)
    if con.confirm('A dry run', 'Try the validation for real now - a test record or file put '
                   'in place, looked for from outside and taken away (no CA asked)?',
                   'Dry run', 'Not now'):
        args = ['--dry-run', got['names']] + (['--challenge', got['challenge']]
                                              if got.get('challenge') else [])
        con.live(lambda: (con.cmd(*args), con.pause()))


KEYS = [('ec-256', 'EC P-256'), ('ec-384', 'EC P-384'), ('rsa-2048', 'RSA 2048'),
        ('rsa-3072', 'RSA 3072'), ('rsa-4096', 'RSA 4096'), ('ed25519', 'Ed25519')]


def _names_of(con, flag):
    return [(r['name'], '%s  (%s)%s' % (r['name'], r.get('kind'), '  - the default'
                                         if r.get('is_default') else ''))
            for r in con._rows(con.out(flag), 'rows')]


def cert_add(con):
    sources = _names_of(con, '--sources')
    vals = _names_of(con, '--validations')
    dflt_s = next((n for n, w in sources if w.endswith('the default')), '')
    dflt_v = next((n for n, w in vals if w.endswith('the default')), '')
    owners = _owner_options(con, '')
    got = con.form('A certificate to keep', [
        {'key': 'name', 'label': 'its name', 'need': True,
         'help': 'What acme calls it: www, vpn-gateway, intranet...'},
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'help': 'The DNS names (and addresses) in it; the first is the common name.'},
        {'key': 'issuer', 'label': 'issuer', 'kind': 'choice', 'value': dflt_s,
         'options': sources or [('', '(no source yet)')],
         'help': 'Where it comes from (Sources).'},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice', 'value': dflt_v,
         'options': [('', '– (not an ACME CA)')] + vals,
         'help': 'For an ACME CA: how the names are proved (Validations).'},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': KEYS}] + (
        # its owner (1.0.126), as the page's new certificate - when there are teams
        [{'key': 'owner', 'label': 'owner', 'kind': 'choice', 'options': owners,
          'help': 'The team it belongs to (Owners and teams): its members and limits.'}]
        if len(owners) > 1 else []))
    if not got:
        return
    args = ['--cert-add', got['name'], '--names', got['names'], '--key-type', got['key_type'],
            '--challenge', got.get('challenge') or '']
    if got.get('issuer'):
        args += ['--issuer', got['issuer']]
    if got.get('owner'):
        args += ['--set', 'owner=%s' % got['owner']]
    if con.act(*args) == 0 and con.confirm('Issue it', 'Issue %s now?' % got['name'],
                                           'Issue it now', 'Later'):
        con.live(lambda: (con.cmd('--renew', got['name']), con.pause()))


def cert_edit(con, r):
    one = (con.out('--cert', r['name']) or {}).get('cert') or r
    sources = _names_of(con, '--sources')
    vals = _names_of(con, '--validations')
    got = con.form('Change ' + r['name'], [
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'value': ', '.join(one.get('names') or [])},
        {'key': 'issuer', 'label': 'issuer', 'kind': 'choice', 'value': one.get('issuer') or '',
         'options': [('', '– (none: imported, or a CSR)')] + sources},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice',
         'value': one.get('challenge') or '', 'options': [('', '–')] + vals},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice',
         'value': one.get('key_type') or 'ec-256', 'options': KEYS},
        {'key': 'auto_renew', 'label': 'renewed by itself', 'kind': 'choice',
         'value': '1' if one.get('auto_renew') else '0', 'options': [('1', 'yes'), ('0', 'no')]},
        {'key': 'renew_days', 'label': 'days before the end', 'kind': 'number',
         'value': str(one.get('renew_days') or ''), 'range': (0, 3650),
         'help': 'Empty or 0: the setting certs_renew_days.'},
        {'key': 'reuse_key', 'label': 'keep its key', 'kind': 'choice',
         'value': '1' if one.get('reuse_key') else '0', 'options': [('0', 'no'), ('1', 'yes')]},
        # a team of Owners and teams, as the page's Owner offers them (1.0.126: typed as
        # text, a misspelt team made a free-text owner no team's members or limits reach)
        {'key': 'owner', 'label': 'owner', 'kind': 'choice', 'value': one.get('owner') or '',
         'options': _owner_options(con, one.get('owner') or '')},
        {'key': 'tags', 'label': 'tags (comma)', 'value': ', '.join(one.get('tags') or [])},
        {'key': 'note', 'label': 'note', 'value': one.get('note') or ''}])
    if not got:
        return
    # only what was changed (1.0.79): every field sent made the event "changed: auto_renew,
    # challenge, issuer, ..." for a note
    def norm(v):
        return re.sub(r'\s*,\s*', ',', str(v if v is not None else '').strip())
    was = {'names': ', '.join(one.get('names') or []), 'issuer': one.get('issuer') or '',
           'challenge': one.get('challenge') or '', 'key_type': one.get('key_type') or 'ec-256',
           'auto_renew': '1' if one.get('auto_renew') else '0',
           'renew_days': str(one.get('renew_days') or '0'),
           'reuse_key': '1' if one.get('reuse_key') else '0', 'owner': one.get('owner') or '',
           'tags': ', '.join(one.get('tags') or []), 'note': one.get('note') or ''}
    now = dict(got, renew_days=got.get('renew_days') or '0')
    args = ['--cert-edit', r['name']]
    for k, opt in (('names', '--names'), ('issuer', '--issuer'), ('challenge', '--challenge'),
                   ('key_type', '--key-type')):
        if norm(now.get(k)) != norm(was[k]):
            args += [opt, now.get(k) or '']
    for k in ('auto_renew', 'renew_days', 'reuse_key', 'owner', 'tags', 'note'):
        if norm(now.get(k)) != norm(was[k]):
            args += ['--set', '%s=%s' % (k, now.get(k) or '')]
    if len(args) == 2:
        con.note('Change ' + r['name'], 'Nothing was changed.')
        return
    con.act(*args)


def jobs(con):
    def load():
        return con._rows(con.out('--jobs', '--limit', '500'), 'rows')
    cols = [('job', lambda r: r.get('id'), 7, None),
            ('when', lambda r: _when(r.get('ts'), '%m-%d %H:%M'), 11, None),
            ('kind', lambda r: r.get('kind'), 7, None),
            ('of', lambda r: r.get('cert_name') or r.get('target') or '-', 24, None),
            ('state', lambda r: r.get('state'), 8,
             lambda r: {'ok': 'ok', 'failed': 'bad', 'running': 'warn'}.get(r.get('state'), '')),
            ('said', lambda r: r.get('said') or '', 60, lambda r: 'dim')]

    def do(r):
        if r.get('state') in ('queued', 'running'):
            what = con.choose('Job %s' % r['id'], [('follow', 'Follow it, live'),
                                                   ('stop', 'Stop it')])
            if what == 'stop':
                con.act('--job-stop', r['id'])
                return
            if what != 'follow':
                return
        con.live(lambda: (con.cmd('--job', r['id']), con.pause()))
    con.pick('Jobs', load, cols, do, 'no job yet')


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------
def deploys(con):
    deploy_list(con)


def deploy_list(con, cert=None, target=None):
    def load():
        if target:
            got = con.out('--target-show', target) or {}
            rows = got.get('deploys') or []
        else:
            rows = con._rows(con.out('--deploys', cert) if cert else con.out('--deploys'),
                             'rows')
        return [{'id': '+', 'cert_name': cert or '', 'target': target or '', '_add': True,
                 'state': 'add one'}] + rows

    cols = [('id', lambda r: r.get('id'), 5, lambda r: 'ok' if r.get('_add') else None),
            ('certificate', lambda r: r.get('cert_name') or '', 24, None),
            ('target', lambda r: r.get('target') or '', 20, None),
            ('state', lambda r: 'outdated' if r.get('outdated') and r.get('state') == 'ok'
             else (r.get('state') or ''), 9,
             lambda r: TONES.get('outdated' if r.get('outdated') else r.get('state') or '', '')),
            ('', lambda r: '' if r.get('_add') else ('on' if r.get('enabled', 1) else 'off'), 3,
             None),
            ('error', lambda r: r.get('last_error') or '', 50,
             lambda r: 'bad' if r.get('last_error') else 'dim')]

    def do(r):
        if r.get('_add'):
            return deploy_add(con, cert, target)
        return deploy_do(con, r)
    return con.pick('Deployments' + (' of %s' % cert if cert else ' to %s' % target if target
                                     else ''), load, cols, do, 'none yet')


def deploy_add(con, cert=None, target=None):
    if not cert:
        certs = [(r['name'], '%s  (%s)' % (r['name'], ', '.join(r.get('names') or [])[:50]))
                 for r in con._rows(con.out('--certs'), 'rows')]
        cert = con.choose('Which certificate', certs)
        if not cert:
            return
    if not target:
        # A connector is not a place to deploy to (1.0.77): only a way to the others.
        ts = [(r['name'], '%s  (%s)' % (r['name'], r.get('kind')))
              for r in con._rows(con.out('--targets'), 'rows') if r.get('kind') != CONNECTOR]
        if not ts:
            con.note('No target', 'There is no target yet: Targets → add one.', 'bad')
            return
        target = con.choose('Where it goes', ts)
        if not target:
            return
    t = (con.out('--target-show', target) or {})
    d = _plugin(con, 'target', t.get('kind')) or {}
    got = module_form(con, '%s on %s' % (cert, target), d.get('deploy_fields') or [])
    if got is None:
        return
    argv, env = got
    if con.act('--deploy-add', cert, target, *argv, env=env) == 0 and \
            con.confirm('Deploy it', 'Put %s on %s now?' % (cert, target), 'Deploy it now',
                        'Later'):
        # Only this one (1.0.77: --deploy CERT ran every deployment of the certificate).
        new = [d for d in con._rows(con.out('--deploys', cert), 'rows')
               if d.get('target') == target]
        if new:
            ident = str(max(int(d['id']) for d in new))
            con.live(lambda: (con.cmd('--deploy-run', ident), con.pause()))
        else:
            con.live(lambda: (con.cmd('--deploy', cert), con.pause()))


def deploy_do(con, r):
    ident = str(r['id'])
    what = con.choose('Deployment %s: %s on %s' % (ident, r.get('cert_name'), r.get('target')),
                      [('run', 'Run it now'), ('edit', 'Change its options'),
                       ('switch', 'Switch it %s' % ('off' if r.get('enabled', 1) else 'on')),
                       ('del', 'Take it away')])
    if what == 'run':
        con.live(lambda: (con.cmd('--deploy-run', ident), con.pause()))
    elif what == 'edit':
        t = con.out('--target-show', r.get('target')) or {}
        d = _plugin(con, 'target', t.get('kind') or r.get('target_kind')) or {}
        got = module_form(con, 'Deployment %s' % ident, d.get('deploy_fields') or [],
                          r.get('options') or {}, r.get('secret_set') or [])
        if got is None:
            return
        argv, env = got
        if argv:
            con.act('--deploy-edit', ident, *argv, env=env)
    elif what == 'switch':
        con.act('--deploy-edit', ident, '--enabled', 'off' if r.get('enabled', 1) else 'on')
    elif what == 'del':
        if con.confirm('Take it away', 'Take the deployment %s away? %s keeps what it has.'
                       % (ident, r.get('target')), 'Take it away', danger=True):
            con.act('--deploy-del', ident, '--yes')


# ---------------------------------------------------------------------------
# Authorities
# ---------------------------------------------------------------------------
def cas(con):
    def load():
        return [{'name': '+ a new root authority', '_new': 'root'},
                {'name': '+ a new intermediate', '_new': 'sub'},
                {'name': '+ import one (a file)', '_new': 'import'}] + \
            con._rows(con.out('--cas'), 'rows')

    cols = [('authority', lambda r: r.get('name') + (' *' if r.get('is_default') else ''), 28,
             lambda r: 'ok' if r.get('_new') else None),
            ('key', lambda r: r.get('key_type') or '', 8, None),
            ('ends', lambda r: '' if r.get('_new') else _when(r.get('not_after')), 10, None),
            ('signs', lambda r: '' if r.get('_new') else ('yes' if r.get('has_key') else 'no'),
             5, None),
            ('subject', lambda r: r.get('subject_dn') or '', 50, lambda r: 'dim')]

    def do(r):
        if r.get('_new') in ('root', 'sub'):
            return ca_new(con, r['_new'])
        if r.get('_new') == 'import':
            got = con.form('Import an authority', [
                {'key': 'file', 'label': 'the file', 'need': True,
                 'help': 'Its certificate and key: a PEM with both, or a PFX / P12.'},
                {'key': 'key', 'label': 'its key (a file)', 'help': 'Where the key is a file '
                 'of its own.'},
                {'key': 'name', 'label': 'its name in acme'},
                {'key': 'pw', 'label': 'locked with a password', 'kind': 'choice',
                 'options': [('0', 'no'), ('1', 'yes')]}])
            if got:
                args = ['--ca-import', got['file']]
                if got.get('key'):
                    args += ['--key', got['key']]
                if got.get('name'):
                    args += ['--name', got['name']]
                if got.get('pw') == '1':
                    con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
                else:
                    con.act(*args)
            return
        return ca_do(con, r)
    con.pick('Authorities', load, cols, do, 'none yet',
             '* the default: offered first for an own-CA source and for signing a CSR')


def ca_new(con, how):
    parents = [(r['name'], r['name']) for r in con._rows(con.out('--cas'), 'rows')
               if r.get('has_key')]
    if how == 'sub' and not parents:
        con.note('No authority', 'There is no authority that can sign an intermediate yet.',
                 'bad')
        return
    fields = [{'key': 'name', 'label': 'its name', 'need': True},
              {'key': 'subject', 'label': 'subject', 'need': True,
               'value': 'CN=Example %s CA,O=Example' % ('Root' if how == 'root' else
                                                       'Issuing'),
               'help': 'CN=..,O=..,OU=..,C=..'},
              {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': [
                  ('ec-384', 'EC P-384'), ('ec-256', 'EC P-256'), ('rsa-4096', 'RSA 4096'),
                  ('rsa-3072', 'RSA 3072')]},
              {'key': 'days', 'label': 'valid for (days)', 'kind': 'number',
               'value': '3650' if how == 'root' else '1825', 'range': (30, 36500)},
              {'key': 'crl_url', 'label': 'CRL address', 'help': 'Written into what it signs '
               '(empty: none).'}]
    if how == 'sub':
        fields.insert(1, {'key': 'parent', 'label': 'signed by', 'kind': 'choice',
                          'options': parents})
    got = con.form('A new %s authority' % ('root' if how == 'root' else 'intermediate'),
                   fields)
    if not got:
        return
    args = ['--ca-create' if how == 'root' else '--ca-sub', got['name'], '--subject',
            got['subject'], '--key-type', got['key_type'], '--days', got['days']]
    if how == 'sub':
        args += ['--parent', got['parent']]
    if got.get('crl_url'):
        args += ['--set', 'crl_url=%s' % got['crl_url']]
    con.act(*args)


def ca_do(con, r):
    name = r['name']
    what = con.choose(name, [('show', 'Show it and what it signed'), ('crl', 'A new CRL'),
                             ('export', 'Export it into a file'),
                             ('sign', 'Sign a CSR from elsewhere'),
                             ('revoke', 'Revoke something it signed'),
                             ('default', 'No default authority any more' if r.get('is_default')
                              else 'Make it the default authority'),
                             ('publish', 'Stop publishing it on acme' if r.get('published')
                              else 'Publish it on acme (/pki/)'),
                             ('pki_urls', 'Use acme\'s own URLs in what it signs'),
                             ('pki_check', 'Check what is published (over HTTP)'),
                             ('del', 'Delete it')])
    if what == 'show':
        con.act('--ca-show', name)
    elif what == 'default':
        con.act('--ca-default', 'none' if r.get('is_default') else name)
    elif what == 'publish':
        con.act('--ca-publish', name, 'off' if r.get('published') else 'on')
    elif what == 'pki_urls':
        if con.confirm('acme\'s own URLs', 'What %s signs from now on carries the CRL and CA '
                       'certificate addresses of acme (/pki/). Certificates issued before keep '
                       'theirs.' % name, 'Use them'):
            con.act('--ca-pki-urls', name)
    elif what == 'pki_check':
        con.live(lambda: (con.cmd('--ca-pki-check', name), con.pause()))
    elif what == 'crl':
        out = con.ask_one('A new CRL of ' + name, 'into the file', '/root/%s.crl.pem' % name)
        if out:
            con.act('--ca-crl', name, '--out', out)
    elif what == 'export':
        got = con.form('Export ' + name, [
            {'key': 'what', 'label': 'what', 'kind': 'choice', 'options': [
                ('cert', 'its certificate (PEM)'), ('cert-der', 'its certificate (DER)'),
                ('chain', 'its chain (PEM)'), ('bundle', 'certificate, chain and CRL'),
                ('crl', 'its CRL (PEM)'), ('p7b', 'PKCS#7'), ('key', 'its private key'),
                ('p12', 'PKCS#12 with its key, locked')]},
            {'key': 'out', 'label': 'into the file', 'value': '/root/%s.pem' % name,
             'need': True}])
        if got:
            args = ['--ca-export', name, '--what', got['what'], '--out', got['out']]
            if got['what'] == 'p12':
                con.live(lambda: (con.cmd(*args), con.pause()))
            else:
                con.act(*args)
    elif what == 'sign':
        got = con.form('Sign a CSR with ' + name, [
            {'key': 'csr', 'label': 'the CSR (a file)', 'need': True},
            {'key': 'out', 'label': 'the certificate into', 'need': True,
             'value': '/root/signed.pem'},
            {'key': 'days', 'label': 'valid for (days)', 'kind': 'number', 'value': '397',
             'range': (1, 36500)},
            {'key': 'eku', 'label': 'for', 'kind': 'choice', 'options': [
                ('serverAuth', 'servers (TLS)'), ('clientAuth', 'clients'),
                ('serverAuth,clientAuth', 'both')]}])
        if got:
            con.act('--ca-sign', name, '--csr', got['csr'], '--out', got['out'], '--days',
                    got['days'], '--set', 'eku=%s' % got['eku'])
    elif what == 'revoke':
        got = con.form('Revoke what %s signed' % name, [
            {'key': 'serial', 'label': 'its serial', 'need': True,
             'help': 'As --ca-show lists it (hex).'},
            {'key': 'reason', 'label': 'why', 'kind': 'choice', 'options': [
                (x, x) for x in ('unspecified', 'keyCompromise', 'superseded',
                                 'cessationOfOperation', 'affiliationChanged')]}])
        if got and con.confirm('Revoke', 'Revoke serial %s signed by %s (%s)? It cannot be '
                               'taken back.' % (got['serial'], name, got['reason']), 'Revoke it',
                               danger=True):            # asked, as a certificate's (1.0.80)
            con.act('--ca-revoke', name, got['serial'], '--reason', got['reason'], '--yes')
    elif what == 'del':
        if con.confirm('Delete ' + name, 'Delete the authority %s and its key? What it signed '
                       'stays valid until it ends.' % name, 'Delete it', danger=True):
            con.act('--ca-del', name, '--yes')


# ---------------------------------------------------------------------------
# acme's own DNS server, the modules
# ---------------------------------------------------------------------------
def dns(con):
    def load():
        got = con.out('--dns-records') or {}
        return [{'id': '+', 'name': '+ add a record', '_add': True}] + \
            list(got.get('records') or [])

    cols = [('id', lambda r: r.get('id'), 5, lambda r: 'ok' if r.get('_add') else None),
            ('name', lambda r: r.get('name'), 36, None),
            ('type', lambda r: r.get('rtype') or '', 6, None),
            ('value', lambda r: r.get('value') or '', 40, None),
            ('ttl', lambda r: r.get('ttl') or '', 6, None),
            ('expires', lambda r: '' if r.get('_add') else (_when(r.get('expires'),
                                                                  '%m-%d %H:%M')
                                                            if r.get('expires') else 'never'),
             12, lambda r: 'dim')]

    def do(r):
        if r.get('_add'):
            got = con.form('A record of acme\'s DNS server', [
                {'key': 'name', 'label': 'name', 'need': True, 'help': '@ for the zone itself.'},
                {'key': 'type', 'label': 'type', 'kind': 'choice', 'options': [
                    (x, x) for x in ('A', 'AAAA', 'TXT', 'CNAME', 'MX', 'NS', 'CAA', 'SRV',
                                     'PTR')]},
                {'key': 'value', 'label': 'value', 'need': True},
                {'key': 'ttl', 'label': 'TTL (s)', 'kind': 'number', 'value': '60',
                 'range': (0, 604800)}])
            if got:
                con.act('--dns-add', got['name'], got['type'], got['value'], '--ttl',
                        got['ttl'] or '60')
            return
        if con.confirm('Take it away', 'Take %s %s %s away?' % (r['name'], r['rtype'],
                                                                 r.get('value')), 'Take it away',
                       danger=True):
            con.act('--dns-del', str(r['id']), '--yes')
    con.pick('acme\'s own DNS server', load, cols, do, 'no record',
             'Its zone and whether it listens: Settings → DNS server (acme --dns-records).')


def modules(con):
    def load():
        got = con.out('--plugins') or {}
        rows = []
        for fam in ('issuer', 'challenge', 'target', 'check'):
            for d in got.get(fam) or []:
                rows.append(dict(d, family=fam))
        return rows
    cols = [('kind', lambda r: r.get('kind'), 16, None),
            ('is a', lambda r: FAMS[r['family']][0], 10, lambda r: 'dim'),
            ('title', lambda r: r.get('title'), 40, None),
            ('vendor', lambda r: r.get('vendor') or '', 18, lambda r: 'dim'),
            ('actions', lambda r: ', '.join(a['key'] for a in r.get('actions') or []), 12,
             None)]
    return con.pick('Modules', load, cols,
             lambda r: con.act('--plugin', '%s/%s' % (r['family'], r['kind'])), 'none')


# ---------------------------------------------------------------------------
# Tests of a certificate, running them, the SSH key, import, self-signed, the source (1.0.77)
# ---------------------------------------------------------------------------
def run_tests(con, what, label):
    """Run the tests (Run the tests… of the page): only run, or with a report by mail / SMS."""
    how = con.choose('Run %s' % label, [('run', 'Only run them'),
                                        ('mail', 'Run them and mail the report'),
                                        ('sms', 'Run them and send the report by SMS'),
                                        ('both', 'Run them, mail and SMS')],
                     'Those switched off are not run.')
    if not how:
        return
    args = ['--check-run', what]
    if how in ('mail', 'both'):
        to = con.ask_one('The report by mail', 'to', 'alerts', 'Addresses separated by commas; '
                         '"alerts": those the alerts go to (Settings → Alerts).')
        if not to:
            return
        args += ['--report-to', to]
    if how in ('sms', 'both'):
        num = con.ask_one('The report by SMS', 'to the numbers', '', '+420..., separated by '
                          'commas.')
        if not num:
            return
        args += ['--sms-to', num]
    con.live(lambda: (con.cmd(*args), con.pause()))


def cert_tests(con, cert):
    def load():
        return [{'id': '+', 'test': '+ attach tests', '_add': True}] + \
            con._rows(con.out('--checks', cert), 'checks')

    cols = [('id', lambda r: r.get('id'), 5, lambda r: 'ok' if r.get('_add') else None),
            ('test', lambda r: r.get('test') or '', 22, None),
            ('', lambda r: '' if r.get('_add') else ('on' if r.get('enabled', 1) else 'off'), 3,
             lambda r: '' if r.get('enabled', 1) else 'dim'),
            ('after', lambda r: '' if r.get('_add') else (
                'none' if r.get('after_target') == '-' else (r.get('after_target') or 'any')
                .replace('\n', ',')), 14, lambda r: 'dim'),
            ('last', lambda r: r.get('last_state') or '', 11,
             lambda r: {'ok': 'ok', 'warn': 'warn'}.get(r.get('last_state'), 'bad')
             if r.get('last_state') else 'dim'),
            ('said', lambda r: r.get('last_said') or '', 50, lambda r: 'dim')]

    def do(r):
        if r.get('_add'):
            have = {x.get('test') for x in con._rows(con.out('--checks', cert), 'checks')}
            tests = [(t['name'], '%s  (%s)' % (t['name'], t.get('kind')))
                     for t in con._rows(con.out('--tests'), 'rows')
                     if t['name'] not in have and t.get('kind') != 'ssh_relay']
            if not tests:
                con.note('No test', 'Every test is attached already, or there is none: '
                         'Certificates → Tests → add one.', 'bad')
                return
            t = con.choose('Attach which test to %s' % cert, tests)
            if t:
                con.act('--check-attach', cert, t)
            return
        ident = str(r['id'])
        what = con.choose('Test %s on %s' % (r.get('test'), cert), [
            ('run', 'Run it now'),
            ('after', 'After which deployment it runs'),
            ('switch', 'Switch it %s for this certificate' % ('off' if r.get('enabled', 1)
                                                               else 'on')),
            ('del', 'Take it off this certificate')], r.get('last_said') or '')
        if what == 'run':
            con.live(lambda: (con.cmd('--check-run', ident), con.pause()))
        elif what == 'after':
            targets = [d.get('target') for d in con._rows(con.out('--deploys', cert), 'rows')]
            pick = con.choose('After which deployment', [
                ('any', 'Any deployment of the certificate'),
                ('-', 'No deployment - by its schedule only')] +
                [(t, 'A deployment on %s' % t) for t in targets if t])
            if pick:
                con.act('--check-after', ident, pick)
        elif what == 'switch':
            con.act('--check-switch', ident, 'off' if r.get('enabled', 1) else 'on')
        elif what == 'del':
            if con.confirm('Take it off', 'Take the test %s off %s?' % (r.get('test'), cert),
                           'Take it off', danger=True):
                con.act('--check-detach', ident)
    got = con.pick('Tests of %s' % cert, load, cols, do, 'none yet')
    if got != 'quit' and con.confirm('Run them', 'Run the tests of %s now?' % cert, 'Run them',
                                     'Not now'):
        run_tests(con, 'cert:' + cert, 'the tests of %s' % cert)
    return got


def ssh_key(con, word, name):
    what = con.choose('The SSH key of %s' % name, [
        ('show', 'How it stands'), ('make', 'Make a new one here (ed25519)'),
        ('make-rsa', 'Make a new one here (RSA 4096)'), ('public', 'Its public half'),
        ('own', 'Your own private key (a file)'), ('try', 'Try to sign in with it'),
        ('forget', 'Forget it')])
    if not what:
        return
    flag = '--%s-key' % word
    if what in ('make', 'make-rsa', 'own') and not con.confirm(
            'A new key', 'If %s has a key already, it is replaced: the server keeps the old public '
            'half until the new one is put there. Go on?' % name, 'Go on', danger=True):
        return                                          # asked first (1.0.80)
    if what == 'make-rsa':
        con.act(flag, name, 'make', 'rsa4096', '--yes')
    elif what == 'own':
        f = con.ask_one('Your own key for %s' % name, 'the file', '', 'A private key '
                        '(OpenSSH or PEM); its passphrase from ACME_KEY_PASSWORD.')
        if f:
            con.act(flag, name, 'own', os.path.expanduser(f), '--yes')
    elif what == 'forget':
        if con.confirm('Forget the key', 'Forget the SSH key of %s?' % name, 'Forget it',
                       danger=True):
            con.act(flag, name, 'forget', '--yes')
    elif what == 'try':
        con.live(lambda: (con.cmd(flag, name, 'try'), con.pause()))
    elif what == 'make':
        con.act(flag, name, what, '--yes')
    else:
        con.act(flag, name, what)


def target_agent(con, name, kind=None):
    """The acme-agent of a target "Server with acme-agent" (1.0.116), as its card on the page:
    acme --target-agent NAME show|system|code|confirm FP|look|policy|renew|update|forget|
    design|discover [cached] [--kind K,K]|adcs-templates [HOST\\CA] (the last two 1.0.126)."""
    what = con.choose('The acme-agent of %s' % name, [
        ('show', 'How it stands'),
        ('system', 'Its server: the OS, addresses, memory, disks, uptime, clock, roles'),
        ('code', 'A one-time join code (an hour, once)'),
        ('confirm', 'Confirm the fingerprint the agent printed'),
        ('look', 'Ask it now (a passive one: the join, as far as acme drives it)'),
        ('policy', 'What its policy allows, as it last said'),
        ('renew', 'Renew its certificate'), ('update', 'Update it to the agent this acme ships'),
        ('design', 'The policy designed for it in acme (never sent)'),
        ('discover', 'What its server runs that takes certificates (discovery: allow discover)'),
        ('discover-kinds', 'The same, only some kinds of services'),
        ('discover-cached', 'What the last discovery found (its agent not asked)')] + (
        # a Windows member server's agent reads the Microsoft CAs (1.0.125)
        [('adcs', 'The Microsoft CAs and their templates, as its agent reads them'),
         ('adcs-one', 'The templates of one Microsoft CA (HOST\\CA)')]
        if kind in (None, 'agent_windows') else []) + [
        ('forget', 'Forget it')])
    if not what:
        return
    flag = '--target-agent'
    if what == 'confirm':
        fp = con.ask_one('Confirm the agent of %s' % name, 'its fingerprint', '', 'As acme-agent '
                         'join printed it on the server (sixteen groups of four) - confirm only '
                         'when it is the same as the one acme shows (How it stands).')
        if fp:
            con.act(flag, name, 'confirm', fp)
    elif what == 'forget':
        if con.confirm('Forget the agent', 'The agent of %s is no longer let in: its certificate '
                       'is refused at once. On the server, acme-agent forget takes its side away.'
                       % name, 'Forget it', danger=True):
            con.act(flag, name, 'forget', '--yes')
    elif what == 'design':
        # as the command line has it (1.0.118): the saved design and how the server's differs
        con.act(flag, name, 'design', 'show')
    elif what == 'discover':
        # 1.0.125: the services and certificates its agent finds (read-only on the server)
        con.live(lambda: (con.cmd(flag, name, 'discover'), con.pause()))
    elif what == 'discover-kinds':
        kinds = con.ask_one('Discovery on %s' % name, 'kinds (comma)', '', 'Only these, e.g. '
                            'nginx,apache (Linux) or iis,rdp (Windows); the agent says which it '
                            'knows when one is not.')
        if kinds:
            con.live(lambda: (con.cmd(flag, name, 'discover', '--kind', kinds), con.pause()))
    elif what == 'discover-cached':
        con.act(flag, name, 'discover', 'cached')
    elif what == 'adcs':
        con.live(lambda: (con.cmd(flag, name, 'adcs-templates'), con.pause()))
    elif what == 'adcs-one':
        ca = con.ask_one('A Microsoft CA', 'HOST\\CA', '', 'Its configuration, as '
                         'certutil says it: ca01.example.local\\Example Issuing CA.')
        if ca:
            con.live(lambda: (con.cmd(flag, name, 'adcs-templates', ca), con.pause()))
    elif what in ('look', 'renew', 'update', 'code'):
        con.live(lambda: (con.cmd(flag, name, what), con.pause()))
    else:
        con.act(flag, name, what)


def agents_menu(con):
    """Settings → Target agents of the pages (1.0.120): the company enrollment codes - one
    code for many servers - and every agent waiting for its fingerprint to be confirmed."""
    flag = '--target-agent'
    return con.sub('Target agents', [
        ('1', 'Agents waiting for confirmation (Enter: compare and confirm one)',
         lambda: agents_waiting(con)),
        ('2', 'Enrollment codes (Enter: revoke one)', lambda: enroll_codes(con)),
        ('3', 'Make an enrollment code: one code for many servers', lambda: enroll_new(con)),
        ('4', 'Every target with an agent', lambda: family(con, 'target')),
        ('5', 'The agents waiting, as acme --target-agent waiting says it',
         lambda: con.act(flag, 'waiting')),
        # as Update all agents… of the pages (1.0.118; in the console 1.0.124)
        ('6', 'Update all agents: every one a newer agent is offered to and its policy allows',
         lambda: agents_update_all(con))])


def agents_update_all(con):
    if con.confirm('Update all agents', 'Every agent that runs an older version than the one this '
                   'acme ships, and whose policy allows it (allow self-update), gets acme\'s own '
                   'signed agent - one by one. The others are said with why not.', 'Update them'):
        con.live(lambda: (con.cmd('--target-agent', 'all', 'update'), con.pause()))


def agents_waiting(con):
    def load():
        return con._rows(con.out('--target-agent', 'waiting'), 'rows')

    cols = [('target', lambda r: r.get('name'), 22, None),
            ('system', lambda r: 'Windows' if r.get('platform') == 'windows' else 'Linux', 8,
             None),
            ('server', lambda r: r.get('fqdn') or r.get('host') or '-', 28, None),
            ('from', lambda r: r.get('ip') or '-', 16, lambda r: 'dim'),
            ('code', lambda r: (r.get('enroll') or {}).get('title') or 'its own', 18,
             lambda r: 'dim'),
            ('fingerprint', lambda r: ' '.join((r.get('fp_words') or '').split()[:4]) + ' …',
             24, lambda r: 'warn')]

    def do(r):
        if con.confirm('Confirm the agent of %s' % r['name'],
                       'Compare with what acme-agent join printed on %s - every group:\n\n%s\n\n'
                       'Confirm only when it is the same.' % (
                           r.get('fqdn') or r.get('host') or r['name'], r.get('fp_words')),
                       'It is the same - confirm'):
            con.act('--target-agent', r['name'], 'confirm', r['fp'])
    return con.pick('Agents waiting for confirmation', load, cols, do,
                    'no agent waits to be confirmed')


def enroll_codes(con):
    def load():
        return con._rows(con.out('--target-agent', 'enroll', 'list'), 'rows')

    tone = {'active': 'ok', 'expired': 'dim', 'used': 'dim', 'revoked': 'bad'}
    cols = [('title', lambda r: r.get('title'), 24, None),
            ('state', lambda r: r.get('state'), 8, lambda r: tone.get(r.get('state'), '')),
            ('mode', lambda r: r.get('mode'), 7, None),
            ('servers', lambda r: '%s of %s' % (r.get('uses'), r.get('most')), 9, None),
            ('until', lambda r: _when(r.get('until'), '%Y-%m-%d %H:%M'), 16, None),
            ('made by', lambda r: r.get('by') or '', 16, lambda r: 'dim'),
            ('', lambda r: 'confirmed automatically' if r.get('auto') else '', 24,
             lambda r: 'bad')]

    def do(r):
        if r.get('state') == 'revoked':
            con.note('Revoked', 'The enrollment code %s is revoked already.' % r['title'])
            return
        if con.confirm('Revoke the enrollment code', 'No other server joins with "%s". The '
                       'servers that joined with it stay (those waiting still wait to be '
                       'confirmed).' % r['title'], 'Revoke it', danger=True):
            con.act('--target-agent', 'enroll', 'revoke', r['id'])
    return con.pick('Enrollment codes', load, cols, do,
                    'no enrollment code yet (Make an enrollment code)')


def enroll_new(con):
    teams = [('', "none - acme's own targets")] + [(t['name'], t['name'])
                                                   for t in _teams(con)]
    got = con.form('An enrollment code: one code for many servers', [
        {'key': 'title', 'label': 'its title', 'need': True,
         'help': 'What you call it - each server that joins with it says it.'},
        {'key': 'mode', 'label': 'the servers\' mode', 'kind': 'choice',
         'options': [('passive', 'passive: acme connects to them'),
                     ('active', 'active: they connect to acme')]},
        {'key': 'port', 'label': 'their port', 'kind': 'number', 'value': '8446',
         'range': (1, 65535), 'when': lambda v: v.get('mode') == 'passive'},
        {'key': 'days', 'label': 'valid for (days)', 'kind': 'number', 'value': '7',
         'range': (1, 365)},
        {'key': 'most', 'label': 'at most (servers)', 'kind': 'number', 'value': '10',
         'range': (1, 10000)},
        {'key': 'auto', 'label': 'confirm automatically', 'kind': 'choice',
         'options': [('0', 'no - a person confirms each'), ('1', 'yes - nobody compares')]}] + (
        # a team's enrollment code (1.0.125 on the pages, --owner on the command line 1.0.126)
        [{'key': 'team', 'label': 'the servers\' team', 'kind': 'choice', 'options': teams,
          'help': 'The servers that join with it become the targets of this team.'}]
        if len(teams) > 1 else []),
        'Each server that joins with it (acme-agent join CODE, the MSI\'s JOINCODE=) becomes a '
        'target of its own and waits for its fingerprint to be confirmed. The agents\' port '
        '(Settings → Target agents) must be on.')
    if not got:
        return
    if got.get('auto') == '1' and not con.confirm(
            'Confirm automatically?', 'Anybody holding this code joins a server to acme '
            'without a person comparing its fingerprint. Only for a code that never leaves your '
            'deployment tooling, for a short time.', 'Confirm automatically', danger=True):
        return
    args = ['--target-agent', 'enroll', 'new', '--title', got['title'].strip(), '--mode',
            got.get('mode') or 'passive', '--days', got.get('days') or '7', '--most',
            got.get('most') or '10']
    if got.get('mode') == 'passive' and got.get('port'):
        args += ['--port', got['port']]
    if got.get('auto') == '1':
        args.append('--auto-confirm')
    if got.get('team'):
        args += ['--owner', got['team']]
    con.live(lambda: (con.cmd(*args), con.pause()))


def cert_import(con, name=None):
    got = con.form('A new version of %s' % name if name else 'Import a certificate', [
        {'key': 'file', 'label': 'the file', 'need': True,
         'help': 'PEM (with its key), DER, PFX / P12, P7B, JKS.'}] + ([] if name else [
            {'key': 'name', 'label': 'its name in acme',
             'help': 'Empty: its common name.'}]) + [
        {'key': 'pw', 'label': 'locked with a password', 'kind': 'choice',
         'options': [('0', 'no'), ('1', 'yes')]}])
    if not got:
        return
    args = ['--import', os.path.expanduser(got['file'].strip())]
    if name:
        args += ['--into', name]            # a new version of it (1.0.80: it made a new one)
    elif got.get('name'):
        args += ['--name', got['name']]
    if got.get('pw') == '1':
        con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
    else:
        con.act(*args)


def cert_selfsigned(con):
    got = con.form('A self-signed certificate', [
        {'key': 'name', 'label': 'its name', 'need': True},
        {'key': 'names', 'label': 'names (comma)', 'need': True},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': KEYS}],
        'Made now, by acme itself - trusted by nobody until told to.')
    if got:
        con.act('--selfsigned', got['name'], '--names', got['names'], '--key-type',
                got['key_type'])


def cert_source(con, r):
    """Change the source (the page's wizard, 1.0.69): its deployments and tests stay."""
    name = r['name']
    sources = _names_of(con, '--sources')
    vals = _names_of(con, '--validations')
    got = con.form('Change the source of %s' % name, [
        {'key': 'issuer', 'label': 'from now on', 'kind': 'choice',
         'value': r.get('issuer') or '',
         'options': [('', 'by hand - imported, renewed by importing')] + sources},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice',
         'value': r.get('challenge') or '', 'options': [('', '– (not an ACME CA)')] + vals},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice',
         'value': r.get('key_type') or 'ec-256', 'options': KEYS}],
        'What stays: its names, deployments, tests, owner, tags. The certificate in use stays '
        'until the new source issues one.')
    if not got:
        return
    if con.act('--cert-edit', name, '--issuer', got['issuer'], '--challenge',
               got['challenge'], '--key-type', got['key_type']) != 0 or not got['issuer']:
        return
    if con.confirm('The first one', 'Issue the first certificate from the new source now? '
                   '(Otherwise at the next renewal.)', 'Issue it now', 'At the next renewal'):
        con.live(lambda: (con.cmd('--renew', name, '--force'), con.pause()))


# ---------------------------------------------------------------------------
# Owners and teams (1.0.126): Settings → Owners and teams of the pages - the tree of teams
# and units, a team's members with their roles, its limits, the roles, the access check of a
# person and what happened in a team; all of it acme --teams, --team-add/-edit/-del, --roles,
# --team-access, --team-activity (acmelib/certs/api_teams.py)
# ---------------------------------------------------------------------------
def _teams(con):
    return con._rows(con.out('--teams'), 'teams')


def _owner_options(con, cur):
    """A certificate's owner as the page's Owner offers it: nobody, the teams, and one typed as
    text before (not defined) - the value it has kept as it is."""
    opts = [('', 'nobody')]
    have = False
    for t in _teams(con):
        if cur and t['name'].lower() == cur.lower():
            opts.append((cur, t['name']))
            have = True
        else:
            opts.append((t['name'], t['name'] + (' (a person)' if t.get('kind') == 'person'
                                                  else '')))
    if cur and not have:
        opts.append((cur, '%s - not defined (typed as text before)' % cur))
    return opts


def _team_choice(con, title, cur, none, always=False, skip=()):
    """A team chosen ('' for `none`; `none` None: no such line), None for Esc; without
    teams '' at once - unless
    `always`, when it is said that there are none."""
    teams = [t for t in _teams(con) if t['name'].lower() not in {x.lower() for x in skip}]
    if not teams and not always:
        return ''
    if not teams:
        con.note(title, 'There is no team yet (Owners and teams).')
        return None
    opts = ([] if none is None else [('', none)]) + [
        (t['name'], '%s%s' % ('  ' * int(t.get('depth') or 0), t['name'])) for t in teams]
    cur_i = next((i for i, o in enumerate(opts) if o[0].lower() == (cur or '').lower()), 0)
    return con.choose(title, opts, cur=cur_i)


def _day(ts):
    return time.strftime('%Y-%m-%d', time.localtime(float(ts)))


def _member_word(m):
    """One member as --members says it: who=rights+roles@YYYY-MM-DD."""
    words = list(m.get('rights') or []) + list(m.get('roles') or [])
    return '%s%s%s' % (m['who'], ('=' + '+'.join(words)) if words else '',
                       ('@' + _day(m['until'])) if m.get('until') else '')


def _day_end(ts):
    """Whether an end is the end of its day - what @YYYY-MM-DD says (teams._date_epoch)."""
    return abs(float(ts) - (time.mktime(time.strptime(_day(ts), '%Y-%m-%d')) + 86399)) < 1


def _member_said(m):
    """Why a member cannot be said in the simple form of --members (it is said as JSON then,
    hunt R t5), or ''."""
    if any(ch in str(m.get('who') or '') for ch in ',=[') or \
            str(m.get('who') or '').strip() != str(m.get('who') or ''):
        return 'the member %s (a DN)' % m['who']
    if any(ch in r for r in list(m.get('roles') or []) + list(m.get('rights') or [])
           for ch in ',+=@'):
        return 'the role of %s' % m['who']
    if m.get('note'):
        return 'the note of the member %s' % m['who']
    if m.get('until') and not _day_end(m['until']):
        return 'the end of %s (a time of the day)' % m['who']
    return ''


def _members_arg(members):
    """The members as --members takes them: the simple form where it says each one as it is,
    else (hunt R t5: a DN, a role with + in it, a member's note, an end at an exact time
    were refused here, or the end rounded to the end of its day) the JSON list."""
    if not any(_member_said(x) for x in members):
        return ','.join(_member_word(x) for x in members)
    return json.dumps([{k: x[k] for k in ('who', 'rights', 'roles', 'until', 'note')
                        if x.get(k) not in (None, '', [])} or {'who': x['who']}
                       for x in members], ensure_ascii=False)


def _policy_words(pol):
    pol = dict(pol or {})
    came = pol.pop('from', None) or {}
    return ['%s %s%s' % (k, json.dumps(v, sort_keys=True, ensure_ascii=False),
                         (' (from %s)' % came[k]) if came.get(k) else '')
            for k, v in sorted(pol.items())]


def team_text(t, teams=()):
    """A team as words: what it is, where it is, its members with their roles, its limits."""
    lines = ['%-14s %s' % ('kind', t.get('kind') or 'team'),
             '%-14s %s' % ('under', t.get('parent') or '- (the top level)')]
    below = [x['name'] for x in teams if (x.get('parent') or '').lower() == t['name'].lower()]
    if below:
        lines.append('%-14s %s' % ('teams below', ', '.join(below)))
    for k, label in (('description', 'description'), ('contact_mail', 'told at'),
                     ('contact_phone', 'phone'), ('note', 'note')):
        if t.get(k):
            lines.append('%-14s %s' % (label, t[k]))
    lines.append('%-14s %s' % ('certificates', t.get('used') or 0))
    lines.append('')
    lines.append('members' if t.get('members') else 'members        none')
    for m in t.get('members') or []:
        words = list(m.get('rights') or []) + list(m.get('roles') or [])
        lines.append('  %-30s %s%s%s' % (m['who'], '+'.join(words) or '-',
                                        (' until %s' % _day(m['until'])) if m.get('until')
                                        else '', ' (expired)' if m.get('expired') else ''))
    own = _policy_words(t.get('policy'))
    eff = _policy_words(t.get('effective'))
    lines.append('')
    lines.append('limits         ' + ('; '.join(own) if own else 'none of its own'))
    if eff and eff != own:
        lines.append('in force       ' + '; '.join(eff))
    return '\n'.join(lines)


def teams_menu(con):
    return con.sub('Owners and teams', [
        ('1', 'The teams and units, as a tree (Enter: what to do with one)',
         lambda: teams_tree(con)),
        ('2', 'Add a team or a unit', lambda: team_add(con)),
        ('3', 'Roles: what each gives (Enter: show)', lambda: roles_list(con)),
        ('4', 'What a person may, in which team, and why (the access check)',
         lambda: team_access(con)),
        ('5', 'What happened in a team', lambda: team_activity(con)),
        ('6', 'The owners and the tags, as acme --teams says them', lambda: con.act('--teams')),
    ])


def teams_tree(con):
    def load():
        return [{'name': '+ add a team or a unit', '_add': True}] + _teams(con)

    cols = [('team', lambda r: r['name'] if r.get('_add') else
             '  ' * int(r.get('depth') or 0) + r['name'], 30,
             lambda r: 'ok' if r.get('_add') else None),
            ('kind', lambda r: r.get('kind') or '', 7, None),
            ('members', lambda r: '' if r.get('_add') else len(r.get('members') or []), 7, None),
            ('certs', lambda r: '' if r.get('_add') else r.get('used') or 0, 5, None),
            ('limits', lambda r: '; '.join(_policy_words(r.get('effective'))), 50,
             lambda r: 'dim')]

    def do(r):
        if r.get('_add'):
            return team_add(con)
        return team_do(con, r)
    return con.pick('Owners and teams', load, cols, do, 'no team yet')


def team_add(con, parent=''):
    teams = _teams(con)
    got = con.form('A team or a unit', [
        {'key': 'name', 'label': 'its name', 'need': True,
         'help': 'What certificates and devices say as their owner.'},
        {'key': 'kind', 'label': 'kind', 'kind': 'choice',
         'options': [('team', 'team'), ('unit', 'unit: teams below it'), ('person', 'person')]},
        {'key': 'parent', 'label': 'under', 'kind': 'choice', 'value': parent,
         'options': [('', '- (the top level)')] + [(t['name'], t['name']) for t in teams]},
        {'key': 'description', 'label': 'description'},
        {'key': 'contact_mail', 'label': 'told at (e-mail)'}])
    if not got:
        return
    args = ['--team-add', got['name'].strip(), '--team-kind', got['kind']]
    if got.get('parent'):
        args += ['--parent', got['parent']]
    for k, opt in (('description', '--description'), ('contact_mail', '--contact-mail')):
        if (got.get(k) or '').strip():
            args += [opt, got[k].strip()]
    if con.act(*args) == 0 and con.confirm('Members', 'Add its members now?', 'Add them',
                                           'Later'):
        one = next((t for t in _teams(con) if t['name'].lower() ==
                    got['name'].strip().lower()), None)
        if one:
            team_members(con, one['name'])


def team_do(con, r):
    name = r['name']
    teams = _teams(con)
    r = next((t for t in teams if t['name'] == name), r)
    what = con.choose(name, [
        ('show', 'Show it: members, roles, limits'),
        ('members', 'Its members (add, change the roles, take away)'),
        ('edit', 'Change it (name, kind, description, told at, note)'),
        ('limits', 'Its limits (profiles, days, approval ...)'),
        ('move', 'Move it under another team (now: %s)' % (r.get('parent') or 'the top level')),
        ('below', 'Add a team below it'),
        ('activity', 'What happened in it'),
        ('del', 'Delete it')],
        '%s, %d member(s), %d certificate(s)' % (r.get('kind') or 'team',
                                                 len(r.get('members') or []),
                                                 int(r.get('used') or 0)))
    if what == 'show':
        text = team_text(r, teams)
        h, _w = con.scr.getmaxyx() if hasattr(con, 'scr') else (50, 100)
        if text.count('\n') + 1 <= h - 8:
            con.note(name, text)
        else:
            con.go_plain(lambda: con.page(name, text))
    elif what == 'members':
        return team_members(con, name)
    elif what == 'edit':
        team_edit(con, r)
    elif what == 'limits':
        team_limits(con, r)
    elif what == 'move':
        to = _team_choice(con, 'Move %s under' % name, r.get('parent') or '',
                          '- (the top level)', always=True, skip=(name,))
        if to is not None and to.lower() != (r.get('parent') or '').lower():
            con.act('--team-edit', name, '--parent', to or '-')
    elif what == 'below':
        team_add(con, name)
    elif what == 'activity':
        team_activity(con, name)
    elif what == 'del':
        team_del(con, r, teams)
    return None


def team_edit(con, r):
    name = r['name']
    got = con.form('Change ' + name, [
        {'key': 'name', 'label': 'its name', 'need': True, 'value': name},
        {'key': 'kind', 'label': 'kind', 'kind': 'choice', 'value': r.get('kind') or 'team',
         'options': [('team', 'team'), ('unit', 'unit: teams below it'), ('person', 'person')]},
        {'key': 'description', 'label': 'description', 'value': r.get('description') or ''},
        {'key': 'contact_mail', 'label': 'told at (e-mail)', 'value': r.get('contact_mail') or ''},
        {'key': 'note', 'label': 'note', 'value': r.get('note') or '',
         'help': 'Empty: taken away.'}])
    if not got:
        return
    args = ['--team-edit', name]
    if got['name'].strip() != name:
        args += ['--name', got['name'].strip()]
    if got['kind'] != (r.get('kind') or 'team'):
        args += ['--team-kind', got['kind']]
    for k, opt in (('description', '--description'), ('contact_mail', '--contact-mail')):
        if (got.get(k) or '').strip() != (r.get(k) or ''):
            args += [opt, (got.get(k) or '').strip()]
    # emptied: taken away (hunt R t5 - acme --team-edit --note '' did not take it away)
    if (got.get('note') or '').strip() != (r.get('note') or '').strip():
        args += ['--note', (got.get('note') or '').strip()]
    if len(args) == 2:
        con.note('Change ' + name, 'Nothing was changed.')
        return
    con.act(*args)


def team_limits(con, r):
    name = r['name']
    have = json.dumps(r.get('policy') or {}, sort_keys=True, ensure_ascii=False)

    def check(v, _vals):
        try:
            return None if isinstance(json.loads(v or '{}'), dict) else 'a JSON object: {...}'
        except ValueError:
            return 'JSON, e.g. {"max_days": 90, "approval": "always"}'
    eff = _policy_words(r.get('effective'))
    v = con.ask_one('The limits of %s' % name, 'limits (JSON)', have, 'Its own: '
                    '{"profiles": ["Web"], "max_days": 90, "approval": "always"} - {} none. '
                    'In force now: %s.' % ('; '.join(eff) if eff else 'none'), need=False,
                    check=check)
    if v is None:
        return
    v = v.strip() or '{}'
    if json.loads(v) == (r.get('policy') or {}):
        con.note('The limits of %s' % name, 'Nothing was changed.')
        return
    con.act('--team-edit', name, '--policy', v)


def _roles(con):
    return con._rows(con.out('--roles'), 'roles')


def team_members(con, name):
    def team():
        return next((t for t in _teams(con) if t['name'] == name), None)

    def load():
        t = team()
        return [{'who': '+ add a member', '_add': True}] + list((t or {}).get('members') or [])

    cols = [('member', lambda m: m['who'], 32, lambda m: 'ok' if m.get('_add') else None),
            ('rights and roles', lambda m: '+'.join(list(m.get('rights') or []) +
                                                    list(m.get('roles') or [])), 30, None),
            ('until', lambda m: (_day(m['until']) + (' (expired)' if m.get('expired') else ''))
             if m.get('until') else '', 22, lambda m: 'bad' if m.get('expired') else 'dim')]

    def do(m):
        t = team()
        if not t:
            return ('%s is not there any more' % name, True)
        members = list(t.get('members') or [])
        if m.get('_add'):
            got = member_form(con, 'A member of %s' % name, {})
            if not got:
                return None
            if any(x['who'].lower() == got['who'].lower() for x in members):
                return ('%s is a member already' % got['who'], True)
            members.append(got)
        else:
            what = con.choose(m['who'], [('edit', 'Change its rights, roles, end'),
                                         ('del', 'Take it away from %s' % name)])
            if what == 'edit':
                got = member_form(con, '%s in %s' % (m['who'], name), m)
                if not got:
                    return None
                members = [got if x['who'] == m['who'] else x for x in members]
            elif what == 'del' and con.confirm('Take a member away', '%s is no longer a member '
                                               'of %s.' % (m['who'], name), 'Take it away',
                                               danger=True):
                members = [x for x in members if x['who'] != m['who']]
            else:
                return None
        con.act('--team-edit', name, '--members', _members_arg(members))
        return None
    return con.pick('Members of %s' % name, load, cols, do, 'no member yet',
                    'local:NAME an account of acme, a user of the directory, group:NAME')


def member_form(con, title, m):
    roles = _roles(con)
    known = {r['name'].lower() for r in roles} | {'view', 'request', 'manage', 'approve'}


    def check_roles(v, _vals):
        bad = [w for w in v.split('+') if w.strip() and w.strip().lower() not in known]
        return ('no such role: %s' % ', '.join(bad)) if bad else None

    def check_until(v, _vals):
        if v.strip() and not re.match(r'^\d{4}-\d{2}-\d{2}$', v.strip()):
            return 'YYYY-MM-DD, or empty'
        if v.strip():
            try:
                # a day that is not one (2026-13-45): a traceback below (hunt R t10)
                time.strptime(v.strip(), '%Y-%m-%d')
            except ValueError:
                return 'YYYY-MM-DD, or empty'
        return None
    got = con.form(title, ([] if m else [
        {'key': 'who', 'label': 'who', 'need': True,
         'help': 'local:NAME (an account of acme), a user of the directory, group:NAME or '
                 'a group\'s DN.'}]) + [
        {'key': 'roles', 'label': 'roles (+ between)', 'need': True, 'check': check_roles,
         'value': '+'.join(list(m.get('roles') or []) + list(m.get('rights') or [])) or
         'Viewer', 'help': 'Roles: %s.' % ', '.join(r['name'] for r in roles)},
        {'key': 'until', 'label': 'until (YYYY-MM-DD)', 'check': check_until,
         'value': _day(m['until']) if m.get('until') else '',
         'help': 'Empty: for good.'}])
    if not got:
        return None
    words = [w.strip() for w in got['roles'].split('+') if w.strip()]
    rights = [w.lower() for w in words if w.lower() in ('view', 'request', 'manage', 'approve')]
    out = {'who': m.get('who') or got['who'].strip(), 'rights': rights,
           'roles': [w for w in words if w.lower() not in rights]}
    if m.get('note'):
        out['note'] = m['note']             # kept: the form does not show it (hunt R t5)
    day = got.get('until', '').strip()
    if day and m.get('until') and day == _day(m['until']):
        out['until'] = m['until']           # its day unchanged: its exact time kept
    elif day:
        out['until'] = time.mktime(time.strptime(day, '%Y-%m-%d')) + 86399
    return out


def team_del(con, r, teams):
    name = r['name']
    args = ['--team-del', name]
    below = [t for t in teams if (t.get('parent') or '').lower() == name.lower()]
    if below:
        to = _team_choice(con, 'The teams below %s go under' % name, r.get('parent') or '',
                          '- (the top level)', always=True,
                          skip=[name] + [t['name'] for t in below])
        if to is None:
            return
        args += ['--parent', to or '-']
    devices = [x for x in con._rows(con.out('--targets'), 'rows')
               if (x.get('owner') or '').lower() == name.lower()]
    # its tests go along with its devices (1.0.128; hunt R u5: a team owning only tests was
    # deleted without the question - its tests became acme's own)
    tests = [x for x in con._rows(con.out('--tests'), 'rows')
             if (x.get('owner') or '').lower() == name.lower()]
    if int(r.get('used') or 0) or devices or tests:
        to = _team_choice(con, 'Its %d certificate(s), %d device(s) and %d test(s) go to' % (
            int(r.get('used') or 0), len(devices), len(tests)), '',
            'nobody (the devices and tests: acme\'s own)', skip=(name,))
        if to is None:
            return
        args += ['--reassign', to or '-']
    if con.confirm('Delete %s' % name, 'Delete the %s %s with its members and limits?' % (
            r.get('kind') or 'team', name), 'Delete it', danger=True):
        con.act(*(args + ['--yes']))


def roles_list(con):
    def load():
        return _roles(con)

    cols = [('role', lambda r: r['name'], 22, None),
            ('', lambda r: 'built in' if r.get('builtin') else 'own', 8, lambda r: 'dim'),
            ('members', lambda r: r.get('used') or 0, 7, None),
            ('capabilities', lambda r: ', '.join(r.get('caps') or []), 60, lambda r: 'dim')]

    def do(r):
        con.note(r['name'], '%s\n\n%s\n\n%s' % (
            'built in' if r.get('builtin') else 'a role of your own (acme --role-add, --role-del)',
            r.get('description') or '-', '\n'.join(r.get('caps') or [])))
    return con.pick('Roles', load, cols, do, 'no role')


def team_access(con):
    who = con.ask_one('The access check', 'who', '', 'local:NAME (an account of acme) or a user '
                      'of the directory: the teams, what each lets and why.')
    if who and who.strip():
        con.act('--team-access', who.strip())


def team_activity(con, name=None):
    if name is None:
        name = _team_choice(con, 'What happened in', '', None, always=True)
        if not name:
            return
    got = con.form('What happened in %s' % name, [
        {'key': 'below', 'label': 'the teams below it too', 'kind': 'choice',
         'options': [('0', 'no'), ('1', 'yes')]},
        {'key': 'limit', 'label': 'at most', 'kind': 'number', 'value': '40',
         'range': (1, 10000)}])
    if not got:
        return
    args = ['--team-activity', name, '--limit', got.get('limit') or '40']
    if got.get('below') == '1':
        args.append('--below')
    con.act(*args)
